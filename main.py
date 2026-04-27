"""
DH-P2P + PTCP Implementation
"""
import argparse
import os
import random
import select
import socket
import subprocess
import sys
import time
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
    socketserver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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

    # ── Helper functions ──────────────────────────────────────────────

    def ptcp_handshake(remote, sign_token):
        remote.request_ptcp(b"\x00\x03\x01\x00")
        res = remote.read_ptcp()
        assert res.body == b"\x00\x03\x01\x00"

        remote.request_ptcp(
            b"\x19\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + sign_token
        )
        res = remote.read_ptcp()
        if len(res.body) == 0:
            res = remote.read_ptcp()
        assert res.body[0] == 0x1A

        remote.request_ptcp(
            b"\x1b\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"
        )
        res = remote.read_ptcp()
        assert len(res.body) == 0
        print("PTCP handshake complete", flush=True)

    def channel_alive(remote, timeout=5):
        remote.settimeout(timeout)
        try:
            while True:
                res = remote.read_ptcp()
                if len(res.body) > 0:
                    remote.request_ptcp()
                    if res.body[0] == 0x13:
                        return True
        except socket.timeout:
            return False
        finally:
            remote.settimeout(None)

    # ── Multi-realm client management ────────────────────────────────

    clients = {}  # realm_id -> {socket, last_keepalive, cseq}
    cseq_base = 100

    def cleanup_client(realm_id, send_disc=True):
        if realm_id not in clients:
            return
        client = clients.pop(realm_id)
        client["socket"].close()
        if send_disc:
            device_remote.request_ptcp(
                b"\x12\x00\x00\x00"
                + realm_id.to_bytes(4, "big")
                + b"\x00\x00\x00\x00"
                + b"DISC",
            )
        print(f"Removed realm={realm_id:#010x}, {len(clients)} active", flush=True)

    def route_ptcp(res):
        """Route incoming PTCP packet to the correct client by realm."""
        if len(res.body) == 0:
            return
        device_remote.request_ptcp()
        if res.body[0] == 0x10:
            payload = PTCPPayload.parse(res.body)
            client = clients.get(payload.realm)
            if client:
                try:
                    client["socket"].send(payload.payload)
                except (ConnectionResetError, BrokenPipeError, OSError):
                    print(f"Send failed realm={payload.realm:#010x}", flush=True)
                    cleanup_client(payload.realm)
        elif res.body[0] == 0x12:
            disc_realm = int.from_bytes(res.body[4:8], "big")
            if disc_realm in clients:
                print(f"DVR DISC realm={disc_realm:#010x}", flush=True)
                cleanup_client(disc_realm, send_disc=False)
        elif res.body[0] != 0x13:
            print(f"PTCP type={res.body[0]:#04x} len={len(res.body)}", flush=True)

    # ── PTCP handshake and main event loop ───────────────────────────

    ptcp_handshake(device_remote, sign)

    print(f"Ready, accepting connections on :{listen_port}", flush=True)

    consecutive_bind_failures = 0

    while True:
        watch = [socketserver, device_remote] + [c["socket"] for c in clients.values()]
        readable, _, _ = select.select(watch, [], [], 1.0)

        # ── Accept new TCP connections ───────────────────────────────
        if socketserver in readable:
            socketclient, address = socketserver.accept()
            print(f"New connection from {address}", flush=True)

            probe_ready, _, _ = select.select([socketclient], [], [], 0)
            if probe_ready:
                probe = socketclient.recv(1, socket.MSG_PEEK)
                if not probe:
                    socketclient.close()
                    continue

            realm_id = random.randint(0, 0xFFFFFFFF)
            print(f"Binding realm={realm_id:#010x}", flush=True)
            device_remote.request_ptcp(
                b"\x11\x00\x00\x00"
                + realm_id.to_bytes(4, "big")
                + b"\x00\x00\x00\x00"
                + b"\x00\x00\x02\x2A"
                + b"\x7f\x00\x00\x01",
            )

            device_remote.settimeout(10)
            bind_ok = False
            try:
                for _ in range(20):
                    res = device_remote.read_ptcp()
                    if len(res.body) > 0 and res.body[0] == 0x12:
                        device_remote.request_ptcp()
                        bind_ok = True
                        break
                    route_ptcp(res)
            except socket.timeout:
                pass
            finally:
                device_remote.settimeout(None)

            if bind_ok:
                clients[realm_id] = {
                    "socket": socketclient,
                    "last_keepalive": time.time(),
                    "cseq": cseq_base,
                }
                cseq_base += 1000
                consecutive_bind_failures = 0
                print(f"Bind OK realm={realm_id:#010x}, {len(clients)} active", flush=True)
            else:
                consecutive_bind_failures += 1
                print(f"Bind FAILED realm={realm_id:#010x} ({consecutive_bind_failures} consecutive)", flush=True)
                socketclient.close()
                if consecutive_bind_failures >= 5:
                    print("PTCP tunnel dead (5 consecutive bind failures), exiting...", flush=True)
                    sys.exit(1)
            continue

        # ── Handle PTCP from DVR ─────────────────────────────────────
        if device_remote in readable:
            res = device_remote.read_ptcp()
            route_ptcp(res)

        # ── Handle data from TCP clients ─────────────────────────────
        for realm_id, client in list(clients.items()):
            if client["socket"] in readable:
                try:
                    data = client["socket"].recv(4096)
                    if not data:
                        print(f"Disconnected realm={realm_id:#010x}", flush=True)
                        cleanup_client(realm_id)
                        continue
                    device_remote.request_ptcp(bytes(PTCPPayload(realm_id, data)))
                    client["last_keepalive"] = time.time()
                except (ConnectionResetError, BrokenPipeError, OSError):
                    print(f"Client error realm={realm_id:#010x}", flush=True)
                    cleanup_client(realm_id)

        # ── RTSP keepalives per realm ────────────────────────────────
        now = time.time()
        for realm_id, client in list(clients.items()):
            if now - client["last_keepalive"] > 25:
                ka = f"OPTIONS * RTSP/1.0\r\nCSeq: {client['cseq']}\r\n\r\n"
                device_remote.request_ptcp(bytes(PTCPPayload(realm_id, ka.encode())))
                client["cseq"] += 1
                client["last_keepalive"] = now


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
