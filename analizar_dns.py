#!/usr/bin/env python3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

AUTH = "172.30.0.70"
ROOT = "172.30.0.10"
VALIDATOR = "172.30.0.101"

ZONAS = [
    ("sinds.test", "zona firmada sin DS en la zona padre"),
    ("dsincorrecto.test", "DS deliberadamente inconsistente"),
    ("expirada.test", "firma RRSIG expirada"),
]

ALGORITMOS_AUTORIZADOS = {
    "8": "RSASHA256",
    "10": "RSASHA512",
    "13": "ECDSAP256SHA256",
    "14": "ECDSAP384SHA384",
}


def consultar(servidor, nombre, tipo, seccion="answer"):
    comando = [
        "dig", f"@{servidor}", nombre, tipo,
        "+dnssec", "+noall", f"+{seccion}"
    ]

    resultado = subprocess.run(
        comando, capture_output=True, text=True, check=False
    )

    return [
        linea for linea in resultado.stdout.splitlines()
        if linea and not linea.startswith(";")
    ]


def mostrar_ttls(lineas):
    ttls = []

    for linea in lineas:
        partes = linea.split()
        if len(partes) >= 4 and partes[1].isdigit():
            ttls.append(partes[1])

    if ttls:
        print("  TTL observados:", ", ".join(sorted(set(ttls))))
    else:
        print("  TTL observados: sin registros en la respuesta")


def obtener_ds_archivo(ruta, propietario):
    try:
        for linea in Path(ruta).read_text().splitlines():
            partes = linea.split()

            if (
                len(partes) >= 7
                and partes[0].rstrip(".") == propietario
                and partes[1] == "IN"
                and partes[2] == "DS"
            ):
                return partes
    except FileNotFoundError:
        pass

    return None


def obtener_ds_desde_ksk(zona):
    carpeta = Path("test/zones")

    for archivo in carpeta.glob(f"K{zona}.*.key"):
        contenido = archivo.read_text()

        if "key-signing key" not in contenido:
            continue

        salida = subprocess.run(
            ["dnssec-dsfromkey", "-2", str(archivo)],
            capture_output=True, text=True, check=False
        ).stdout.strip()

        partes = salida.split()

        if len(partes) >= 7:
            return partes

    return None


def revisar_dnskey(zona):
    print(f"\n[DNSKEY] {zona}")
    lineas = consultar(AUTH, zona, "DNSKEY")
    encontrada = False

    for linea in lineas:
        partes = linea.split()

        if len(partes) < 8 or partes[3] != "DNSKEY":
            continue

        encontrada = True
        bandera = partes[4]
        algoritmo = partes[6]

        if bandera == "257":
            tipo = "KSK"
        elif bandera == "256":
            tipo = "ZSK"
        else:
            tipo = "otro tipo"

        nombre_algoritmo = ALGORITMOS_AUTORIZADOS.get(
            algoritmo, "no autorizado"
        )
        estado = (
            "autorizado"
            if algoritmo in ALGORITMOS_AUTORIZADOS
            else "no autorizado"
        )

        print(
            f"  {tipo}: flags={bandera}, algoritmo={algoritmo} "
            f"({nombre_algoritmo}), estado={estado}"
        )

    if not encontrada:
        print("  No se encontraron registros DNSKEY.")

    mostrar_ttls(lineas)


def revisar_rrsig(zona):
    print(f"\n[RRSIG] {zona}")
    lineas = consultar(AUTH, f"www.{zona}", "A")
    ahora = datetime.now(timezone.utc)
    encontrada = False

    for linea in lineas:
        partes = linea.split()

        if len(partes) < 12 or partes[3] != "RRSIG":
            continue

        encontrada = True
        inicio = datetime.strptime(
            partes[9], "%Y%m%d%H%M%S"
        ).replace(tzinfo=timezone.utc)

        expiracion = datetime.strptime(
            partes[8], "%Y%m%d%H%M%S"
        ).replace(tzinfo=timezone.utc)

        if ahora > expiracion:
            estado = "EXPIRADA"
        elif ahora < inicio:
            estado = "AÚN NO VÁLIDA"
        else:
            estado = "VÁLIDA"

        print(f"  RRSet firmado: {partes[4]}")
        print(f"  Algoritmo: {partes[5]} | Key tag: {partes[10]}")
        print(f"  Inicio: {inicio.isoformat()}")
        print(f"  Expiración: {expiracion.isoformat()}")
        print(f"  Autor de la firma: {partes[11]}")
        print(f"  Estado: {estado}")

    if not encontrada:
        print("  No se encontró un registro RRSIG.")

    mostrar_ttls(lineas)


def revisar_ds(zona, descripcion):
    print(f"\n[DS] {zona} ({descripcion})")
    propietario = zona.split(".")[0]

    ds_padre = obtener_ds_archivo("test/zones/db.test", propietario)
    ds_hijo = obtener_ds_desde_ksk(zona)

    if not ds_padre:
        print("  No existe DS en la zona padre.")
        print("  Estado de cadena: insegura; la confianza se corta en el padre.")
        return

    print(
        f"  DS en padre: key tag={ds_padre[3]}, "
        f"algoritmo={ds_padre[4]}, digest type={ds_padre[5]}"
    )
    print("  TTL configurado en la zona padre: 3600")

    if not ds_hijo:
        print("  No fue posible obtener el DS esperado desde la KSK hija.")
        return

    print(
        f"  DS esperado por la KSK hija: key tag={ds_hijo[3]}, "
        f"algoritmo={ds_hijo[4]}, digest type={ds_hijo[5]}"
    )

    if ds_padre[3:7] == ds_hijo[3:7]:
        print("  Estado de cadena: DS coherente con la KSK hija.")
    else:
        print("  Estado de cadena: DS INCONSISTENTE con la KSK hija.")


def revisar_nsec(zona):
    print(f"\n[NSEC/NSEC3] {zona}")
    inexistente = f"noexiste.{zona}"
    lineas = consultar(AUTH, inexistente, "A", "authority")
    nsec = [linea for linea in lineas if " NSEC " in f" {linea} "]
    nsec3 = [linea for linea in lineas if " NSEC3 " in f" {linea} "]
    nsec3param = consultar(AUTH, zona, "NSEC3PARAM")

    if nsec:
        print("  Mecanismo detectado: NSEC.")
        for linea in nsec:
            partes = linea.split()
            if len(partes) >= 6:
                print(
                    f"  Zone walking posible: {partes[0]} -> {partes[4]}"
                )
    elif nsec3 or nsec3param:
        print("  Mecanismo detectado: NSEC3/NSEC3PARAM.")
        print("  El nombre siguiente se oculta mediante hashes; mitiga el zone walking directo.")
    else:
        print("  No se detectó NSEC ni NSEC3 en la respuesta.")


def revisar_cadena_raiz():
    print("\n[Cadena raíz -> test]")

    ds_raiz = obtener_ds_archivo("root/zones/db.root", "test")

    if ds_raiz:
        print(
            f"  DS de test en raíz: key tag={ds_raiz[3]}, "
            f"algoritmo={ds_raiz[4]}, digest type={ds_raiz[5]}"
        )
        print("  Dependencia criptográfica raíz -> test: presente.")
    else:
        print("  No se encontró DS de test en la zona raíz.")

    salida = subprocess.run(
        [
            "dig", f"@{VALIDATOR}", "www.expirada.test", "A",
            "+dnssec", "+noall", "+comments"
        ],
        capture_output=True, text=True, check=False
    ).stdout

    if "SERVFAIL" in salida:
        print("  El recursivo validador rechaza la firma expirada de expirada.test.")
    else:
        print("  El recursivo validador no reportó error para expirada.test.")


def main():
    print("=== Verificador DNSSEC - Actividad 4 ===")

    for zona, descripcion in ZONAS:
        revisar_dnskey(zona)
        revisar_rrsig(zona)
        revisar_ds(zona, descripcion)
        revisar_nsec(zona)

    revisar_cadena_raiz()
    print("\nVerificación finalizada.")


if __name__ == "__main__":
    main()
