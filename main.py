"""
DH-P2P + PTCP Implementation
"""
import argparse
import datetime
import os
import random
import select
import socket
import subprocess
import sys
from urllib.parse import quote

from helpers import (
    MAIN_PORT,
    MAIN_SERVER,
    UDP,
    PTCPPayload,
    get_auth,
    get_dec,
    get_enc,
    get_key,
    get_nonce,
)


def main(serial, dtype=0, username=None, password=None, debug=False, randsalt=None):
    socketserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_port = int(os.environ.get("DAHUA_LISTEN_PORT", "554"))
    socketserver.bind(("0.0.0.0", listen_port))
    socketserver.listen(5)
    print(f"Listening on port {listen_port}")

    if debug:
        subprocess.Popen(
            [
                "ffplay",
                "-rtsp_transport",
                "tcp",
                "-i",
                f"rtsp://{username}:{quote(password)}@127.0.0.1/cam/realmonitor?channel=6&subtype=0",
            ]
        )

    main_remote = UDP(MAIN_SERVER, MAIN_PORT, debug)
    res = main_remote.request("/probe/p2psrv")

    res = main_remote.request(f"/online/p2psrv/{serial}")

    p2psrv_server, p2psrv_port = res["data"]["body"]["US"].split(":")
    p2psrv_port = int(p2psrv_port)

    p2psrv_remote = UDP(p2psrv_server, p2psrv_port, debug)
    res = p2psrv_remote.request(f"/probe/device/{serial}")
    res = p2psrv_remote.request(f"/info/device/{serial}")
    p2psrv_remote.close()

    res = main_remote.request("/online/relay")
    relay_server, relay_port = res["data"]["body"]["Address"].split(":")
    relay_port = int(relay_port)

    device_remote = UDP(MAIN_SERVER, MAIN_PORT, debug)

    laddr = f"127.0.0.1:{device_remote.lport}"
    ipaddr = f"<IpEncrpt>true</IpEncrpt><LocalAddr>{laddr}</LocalAddr>"
    auth = ""
    aid = random.randbytes(8)

    if dtype > 0:
        key = get_key(username, password, randsalt)
        nonce = get_nonce()

        laddr = get_enc(key, nonce, laddr)
        ipaddr = f"<IpEncrptV2>true</IpEncrptV2><LocalAddr>{laddr}</LocalAddr>"
        auth = get_auth(username, key, nonce, laddr, randsalt)

    res = device_remote.request(
        f"/device/{serial}/p2p-channel",
        f"<body>{auth}<Identify>{' '.join(f'{b:x}' for b in aid)}</Identify>"
        f"{ipaddr}<version>5.0.0</version></body>",
        should_read=False,
    )

    main_remote.rhost = relay_server
    main_remote.rport = relay_port
    res = main_remote.request("/relay/agent")
    token = res["data"]["body"]["Token"]
    agent_server, agent_port = res["data"]["body"]["Agent"].split(":")
    agent_port = int(agent_port)

    main_remote.rhost = agent_server
    main_remote.rport = agent_port
    res = main_remote.request(
        f"/relay/start/{token}",
        "<body><Client>:0</Client></body>",
    )

    res = device_remote.read(return_error=True)
    if res["code"] < 200:
        res = device_remote.read(return_error=True)

    if res["code"] >= 400:
        print("Error:", res["status"])

        if dtype == 0 and res["code"] == 403:
            print("Device requires authentication when creating P2P channel.")
            print("Try again with:")
            print(
                f"main.py --type 1 --username <username> --password <password> {serial}"
            )

        sys.exit(1)

    device_laddr = res["data"]["body"]["LocalAddr"]
    if dtype > 0:
        nonce = res["data"]["body"]["Nonce"]
        device_laddr = get_dec(key, nonce, device_laddr)

    device_server, device_port = res["data"]["body"]["PubAddr"].split(":")
    device_port = int(device_port)
    device_remote.rhost = device_server
    device_remote.rport = device_port

    main_remote.rhost = MAIN_SERVER
    main_remote.rport = MAIN_PORT

    if dtype > 0:
        nonce2 = get_nonce()
        auth = get_auth(username, key, nonce2, randsalt=randsalt)

    res = main_remote.request(
        f"/device/{serial}/relay-channel",
        f"<body>{auth}<agentAddr>{agent_server}:{agent_port}</agentAddr></body>",
        should_read=False,
    )

    main_remote.rhost = agent_server
    main_remote.rport = agent_port
    # TODO check timeout
    res = main_remote.read()

    main_remote.request_ptcp(b"\x00\x03\x01\x00")
    res = main_remote.read_ptcp()

    main_remote.request_ptcp(b"\x17\x00\x00\x00" + b"\x00\x00\x00\x00\x00\x00\x00\x00")
    res = main_remote.read_ptcp()
    while len(res.body) == 0:
        res = main_remote.read_ptcp()
    sign = res.body[12:]

    main_remote.request_ptcp()

    device_remote.rhost = device_server
    device_remote.rport = device_port

    aid = bytes(0xFF - b for b in aid)
    cookie = random.randbytes(4)
    trasn_id = random.randbytes(12)
    eaddr = device_port.to_bytes(2) + socket.inet_aton(device_server)
    eaddr = bytes(0xFF - b for b in eaddr)

    stun_init = (
        b"\xff\xfe\xff\xe7"
        + cookie
        + trasn_id
        + b"\x7f\xd5\xff\xf7"
        + aid
        + b"\xff\xfb\xff\xf7\xff\xfe"
        + eaddr
    )

    local_ip, local_port_str = device_laddr.split(":")
    local_port_val = int(local_port_str)
    print(f":{device_remote.lport} >>> {local_ip}:{local_port_val} (LocalAddr)")
    print("".join(f"\\x{b:02X}" for b in stun_init))
    device_remote.sendto(stun_init, (local_ip, local_port_val))

    print(f":{device_remote.lport} >>> {device_remote.rhost}:{device_remote.rport} (PubAddr)")
    print("".join(f"\\x{b:02X}" for b in stun_init))
    device_remote.send(stun_init)

    import time
    stun_response = None
    device_remote.settimeout(2)
    deadline = time.time() + 10
    attempt = 0
    while time.time() < deadline:
        try:
            data, addr = device_remote.recvfrom(4096)
            magic = data[:4]
            print(f"STUN <<< {addr[0]}:{addr[1]} magic={magic.hex()} len={len(data)}")
            if magic == b"\xfe\xfe\xff\xe7":
                stun_response = data
                print("Got STUN response (fefeffe7)")
                break
            elif magic == b"\xff\xfe\xff\xe7":
                print("Got device cross-STUN init (fffeffe7), responding...")
                resp = (
                    b"\xfe\xfe\xff\xe7"
                    + data[4:8]
                    + data[8:20]
                    + b"\x7f\xd6\xff\xf7"
                    + aid
                    + b"\xff\xfb\xff\xf7\xff\xfe"
                    + data[34:40]
                )
                device_remote.sendto(resp, addr)
                print(f"STUN >>> {addr[0]}:{addr[1]} response sent")
            else:
                print(f"Unknown magic: {magic.hex()}")
        except socket.timeout:
            attempt += 1
            if attempt <= 2:
                print(f"Retransmit STUN init (attempt {attempt})")
                device_remote.send(stun_init)
            continue

    if stun_response is None:
        print("No STUN response received, exiting.")
        sys.exit(1)

    confirm = (
        b"\xfe\xfe\xff\xf3"
        + cookie
        + trasn_id
        + b"\x7f\xd6\xff\xf7"
        + aid
    )
    for _ in range(5):
        print("Confirm >>>")
        device_remote.send(confirm)

    time.sleep(0.3)
    device_remote.settimeout(0.5)
    while True:
        try:
            data, addr = device_remote.recvfrom(4096)
            print(f"Drain <<< {addr[0]}:{addr[1]} magic={data[:4].hex()} len={len(data)}")
        except socket.timeout:
            break
    device_remote.settimeout(None)

    device_remote.request_ptcp(b"\x00\x03\x01\x00")
    res = device_remote.read_ptcp()
    assert res.body == b"\x00\x03\x01\x00"

    device_remote.request_ptcp(
        b"\x19\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + sign
    )
    res = device_remote.read_ptcp()
    if len(res.body) == 0:
        res = device_remote.read_ptcp()
    assert res.body[0] == 0x1A

    device_remote.request_ptcp(
        b"\x1b\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"
    )
    res = device_remote.read_ptcp()
    assert len(res.body) == 0

    print("Ready to connect")
    print(f"Test with: rtsp://127.0.0.1:{listen_port}/cam/realmonitor?channel=1&subtype=0")
    while True:
        ready, _, _ = select.select([socketserver], [], [], 0.1)

        if not ready:
            ptcp_ready, _, _ = select.select([device_remote], [], [], 0)

            if not ptcp_ready:
                continue

            # only simplex, duplex is not supported
            res = device_remote.read_ptcp()
            if len(res.body) == 0:
                continue

            if res.body[0] != 0x13:
                print(f"Unexpected PTCP keepalive type: {res.body[0]:#04x} body={res.body[:20].hex()}", flush=True)
            device_remote.request_ptcp()

            continue

        socketclient, address = socketserver.accept()
        print(f"Connection from {address}", flush=True)

        client_ready, _, _ = select.select([socketclient], [], [], 0)
        if client_ready:
            probe = socketclient.recv(1, socket.MSG_PEEK)
            if not probe:
                print("Stale connection (already closed), skipping", flush=True)
                socketclient.close()
                continue

        realm_id = random.randint(0x00000000, 0xFFFFFFFF)
        print(f"PTCP Bind: realm={realm_id:#010x}", flush=True)
        device_remote.request_ptcp(
            b"\x11\x00\x00\x00"
            + realm_id.to_bytes(4, "big")
            + b"\x00\x00\x00\x00"
            # port 554
            + b"\x00\x00\x02\x2A"
            + b"\x7f\x00\x00\x01",
        )
        device_remote.settimeout(10)
        try:
            for _bind_attempt in range(5):
                res = device_remote.read_ptcp()
                if len(res.body) > 0:
                    break
            assert res.body[0] == 0x12, f"Expected 0x12, got {res.body[0]:#04x}"
            print("PTCP Bind OK", flush=True)
        except (socket.timeout, AssertionError) as e:
            print(f"PTCP Bind failed: {e}", flush=True)
            socketclient.close()
            continue
        finally:
            device_remote.settimeout(None)

        try:
            while True:
                ptcp_ready, _, _ = select.select([device_remote], [], [], 0.1)

                while ptcp_ready:
                    res = device_remote.read_ptcp()

                    if len(res.body) > 0:
                        device_remote.request_ptcp()

                        if res.body[0] == 0x10:
                            body = PTCPPayload.parse(res.body)
                            print(f"DVR >>> TCP {len(body.payload)}B", flush=True)
                            socketclient.send(body.payload)
                        else:
                            print(f"PTCP <<< type={res.body[0]:#04x} len={len(res.body)}", flush=True)

                    ptcp_ready, _, _ = select.select([device_remote], [], [], 0.1)

                client_ready, _, _ = select.select([socketclient], [], [], 0)

                if not client_ready:
                    continue

                data = socketclient.recv(4096)

                if not data:
                    print("Client disconnected", flush=True)
                    break

                print(f"TCP >>> PTCP {len(data)}B", flush=True)
                device_remote.request_ptcp(bytes(PTCPPayload(realm_id, data)))

        except ConnectionResetError:
            print("Connection reset by peer", flush=True)
        except BrokenPipeError:
            print("Broken pipe", flush=True)
        finally:
            print("Cleaning up connection", flush=True)
            device_remote.request_ptcp(
                b"\x12\x00\x00\x00"
                + realm_id.to_bytes(4, "big")
                + b"\x00\x00\x00\x00"
                + b"DISC"
            )

            device_remote.settimeout(5)
            try:
                res = device_remote.read_ptcp()
                while len(res.body) == 0 or res.body[0] == 0x10:
                    if len(res.body) > 0:
                        device_remote.request_ptcp()
                    res = device_remote.read_ptcp()
                if res.body[0] == 0x12:
                    device_remote.request_ptcp()
            except socket.timeout:
                print("Cleanup timeout, continuing", flush=True)
            finally:
                device_remote.settimeout(None)

            socketclient.close()
            print("Connection closed", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("serial", help="Serial number of the camera")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("-t", "--type", type=int, help="Type of the camera", default=0)
    parser.add_argument("-u", "--username", help="Username of the camera")
    parser.add_argument("-p", "--password", help="Password of the camera")
    parser.add_argument("-s", "--randsalt", help="Device RandSalt (from Info blob)")
    args = parser.parse_args()

    if args.username is None or args.password is None:
        if args.type > 0:
            parser.error("Username and password are required for type > 0")
        elif args.debug:
            parser.error("Username and password are required in debug mode")

    if args.serial:
        main(args.serial, args.type, args.username, args.password, args.debug, args.randsalt)
