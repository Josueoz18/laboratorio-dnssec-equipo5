import subprocess

ARCHIVO = "/tmp/traza_dns.pcapng"

consultas = [
    ("SOA", "unsigned", "6"),
    ("NS", "unsigned", "2"),
    ("A", "www.alpha.unsigned", "1")
]

print("Registros DNS extraídos de la traza\n")

for nombre_tipo, dominio, tipo_num in consultas:

    comando = [
        "tshark",
        "-r", ARCHIVO,
        "-Y",
        f'dns.flags.response == 1 && '
        f'dns.qry.name == "{dominio}" && '
        f'dns.qry.type == {tipo_num} && '
        f'ip.src == 172.30.0.100 && ip.dst == 172.30.0.1',
        "-T", "fields",
        "-E", "separator=|",
        "-E", "occurrence=f",
        "-e", "dns.qry.name",
        "-e", "dns.resp.ttl",
        "-e", "dns.a",
        "-e", "dns.ns",
        "-e", "dns.soa.mname",
        "-e", "dns.soa.rname",
        "-e", "dns.soa.serial_number",
        "-e", "dns.soa.refresh_interval",
        "-e", "dns.soa.retry_interval",
        "-e", "dns.soa.expire_limit",
        "-e", "dns.soa.minimum_ttl"
    ]

    resultado = subprocess.run(
        comando,
        capture_output=True,
        text=True
    )

    lineas = resultado.stdout.strip().splitlines()

    if not lineas:
        print(f"{nombre_tipo}: no encontrado")
        print("-" * 45)
        continue

    campos = lineas[-1].split("|")

    while len(campos) < 11:
        campos.append("")

    (
        consulta,
        ttl,
        direccion,
        servidor_ns,
        soa_mname,
        soa_rname,
        serial,
        refresh,
        retry,
        expire,
        minimum
    ) = campos

    print(f"Registro: {nombre_tipo}")
    print(f"Dominio: {consulta}")
    print(f"TTL: {ttl} segundos")

    if nombre_tipo == "A":
        print(f"Dirección IPv4: {direccion}")

    elif nombre_tipo == "NS":
        print(f"Servidor de nombres: {servidor_ns}")

    elif nombre_tipo == "SOA":
        print(f"Servidor principal: {soa_mname}")
        print(f"Responsable: {soa_rname}")
        print(f"Serial: {serial}")
        print(f"Refresh: {refresh}")
        print(f"Retry: {retry}")
        print(f"Expire: {expire}")
        print(f"Minimum TTL: {minimum}")

    print("-" * 45)
