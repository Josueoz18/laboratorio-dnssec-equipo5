# Laboratorio de Pruebas para DNSSEC

Repositorio del laboratorio final de pruebas DNSSEC desarrollado por el Equipo 5 para la materia Aplicación de Criptografía y Seguridad MA2005B.

El objetivo del laboratorio es mostrar el funcionamiento de DNSSEC en distintos escenarios y comparar el comportamiento de servidores DNS cuando la validación está correctamente configurada, cuando la cadena de confianza está incompleta y cuando existen errores intencionales.

## Contenido del repositorio

El repositorio incluye:

- Configuración de servidores DNS con BIND.
- Zonas DNS firmadas y no firmadas.
- Servidores autoritativos.
- Servidores recursivos con y sin validación DNSSEC.
- Escenario con una zona firmada sin registro DS en la zona padre.
- Escenario con un registro DS incorrecto.
- Escenario con una firma DNSSEC expirada.
- Archivo `docker-compose.yml` para levantar el laboratorio.
- Herramienta `analizar_dns.py` para automatizar distintas verificaciones relacionadas con DNSSEC.
- Archivos de captura de tráfico en formato `.pcapng`.

## Estructura general

El laboratorio incluye las siguientes zonas y servicios:

- `root`
- `unsigned`
- `signed`
- `alpha`
- `beta`
- `gamma`
- `delta`
- `epsilon`
- `zeta`
- `eta`
- `theta`
- `iota`
- `test`
- `recursive1`
- `recursive2`

`recursive1` funciona como servidor recursivo sin validación DNSSEC.

`recursive2` funciona como servidor recursivo con validación DNSSEC.

## Requisitos

Para ejecutar el laboratorio se requiere:

- Docker
- Docker Compose
- Python 3
- Herramientas DNS como `dig`

## Ejecución del laboratorio

Desde la carpeta principal del repositorio, ejecutar:

```bash
docker compose up -d
```

Para verificar que los contenedores se encuentren activos:

```bash
docker compose ps
```

Para detener el laboratorio:

```bash
docker compose down
```

## Herramienta de análisis

El archivo `analizar_dns.py` permite automatizar distintas comprobaciones del laboratorio, incluyendo la revisión de:

- Registros DNSKEY
- Firmas RRSIG
- Registros DS
- Cadena de confianza
- TTL
- NSEC y NSEC3
- Inconsistencias en registros DS
- Firmas expiradas

Para ejecutar la herramienta:

```bash
python3 analizar_dns.py
```

## Escenarios de prueba

Entre los escenarios implementados se encuentran:

### Zona correctamente validada

Permite comprobar el comportamiento de una zona correctamente firmada y con una cadena de confianza completa.

### Zona firmada sin DS

La zona contiene firmas DNSSEC, pero no existe un registro DS en su zona padre, por lo que la cadena de confianza queda incompleta.

### DS incorrecto

Se configura intencionalmente un registro DS que no corresponde con la clave de la zona hija. Un servidor que valida DNSSEC rechaza la respuesta.

### Firma expirada

Se utiliza una zona con una firma DNSSEC expirada para comprobar que un servidor validador detecta la firma como no válida y rechaza la respuesta.

## Equipo 5

- Josué Olvera Zozaya
- Héctor Daniel Jasso Guerrero
- Victoria Catherine Bagliéri
- Rafael Sánchez Ramírez

## Materia

Aplicación de Criptografía y Seguridad  
MA2005B

## Socio formador

NIC México
