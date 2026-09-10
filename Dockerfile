# Arx Core — imagen mínima.
#
# Nota: Arx es un agente que defiende el HOST donde vive; la protección real se
# instala en el servidor (.deb). Esta imagen sirve para probar el CLI, correr el
# reconocimiento, o desplegar Arx contra un objetivo de laboratorio. Para que
# defienda al host desde un contenedor haría falta acceso a los namespaces del
# host y privilegios — despliegue avanzado, no el camino por defecto.
FROM python:3.12-slim

COPY dist/arx.pyz /usr/lib/arx/arx.pyz
RUN printf '#!/bin/sh\nexec python3 /usr/lib/arx/arx.pyz "$@"\n' > /usr/bin/arx \
    && chmod 0755 /usr/bin/arx

# Estado y config dentro del contenedor (montar un volumen para persistir)
ENV ARX_STATE_DIR=/var/lib/arx ARX_CONFIG_DIR=/etc/arx

ENTRYPOINT ["arx"]
CMD ["--help"]
