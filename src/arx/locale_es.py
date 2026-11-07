"""Arx · catálogo español. La clave es el texto fuente (inglés) tal como aparece en tr(...)."""

ES = {
    "{k} appeared since the baseline was sealed":
        "{k} apareció después de sellar la línea base",
    "{k} disappeared since the baseline was sealed":
        "{k} desapareció después de sellar la línea base",
    "local_url must be http(s)":
        "local_url debe ser http(s)",
    "service {unit} was updated from {old} to {new}":
        "el servicio {unit} se actualizó de {old} a {new}",
    "{unit} was updated to {new} and cannot be trusted: {reason}":
        "{unit} se actualizó a {new} y no es de fiar: {reason}",
    "an update is when a signed but poisoned version arrives":
        "una actualización es cuando llega una versión firmada pero envenenada",
    "trust {score:.2f} of {min:.2f}":
        "confianza {score:.2f} de {min:.2f}",
    "touches SSH authorized keys":
        "toca las llaves SSH autorizadas",
    "sets a SUID/SGID bit":
        "pone un bit SUID/SGID",
    "installs a scheduled task":
        "instala una tarea programada",
    "creates a second root account":
        "crea una segunda cuenta root",
    "downloads from a bare IP":
        "descarga desde una IP directa",
    "injects a library into every program":
        "inyecta una librería en todos los programas",
    "every file matches what dpkg installed":
        "todos los ficheros coinciden con lo que instaló dpkg",
    "nothing known against this version":
        "nada conocido contra esta versión",
    "its install scripts do nothing suspicious":
        "sus scripts de instalación no hacen nada sospechoso",
    "not reproducible ({status})":
        "no reproducible ({status})",
    "installed {days:.1f} days ago":
        "instalado hace {days:.1f} días",
    "dpkg --verify did not answer":
        "dpkg --verify no respondió",
    "changed since installed: {files}":
        "cambiado desde que se instaló: {files}",
    "apt is not available":
        "apt no está disponible",
    "{n} files identical to the official package":
        "{n} ficheros idénticos al paquete oficial",
    "no vulnerability database for this distribution":
        "no hay base de vulnerabilidades para esta distribución",
    "known as malicious: {ids}":
        "conocido como malicioso: {ids}",
    "{n} known vulnerabilities, none malicious":
        "{n} vulnerabilidades conocidas, ninguna maliciosa",
    "no independent rebuilder for this distribution":
        "no hay reconstrucción independiente para esta distribución",
    "the rebuilder has not seen this version":
        "la reconstrucción independiente no ha visto esta versión",
    "independently rebuilt from source, identical":
        "reconstruido de forma independiente desde el código fuente, idéntico",
    "installed long ago":
        "instalado hace tiempo",
    "unknown package":
        "paquete desconocido",
    "could not download the official package":
        "no se pudo descargar el paquete oficial",
    "package too large to compare":
        "paquete demasiado grande para comparar",
    "differs from the official package: {files}":
        "difiere del paquete oficial: {files}",
    "no connection to the vulnerability database":
        "sin conexión con la base de vulnerabilidades",
    "no connection to the rebuilder":
        "sin conexión con la reconstrucción independiente",
    "no install log":
        "sin registro de instalación",
    "unreadable install log":
        "registro de instalación ilegible",
    "could not open the official package":
        "no se pudo abrir el paquete oficial",
    "the model flagged {dest} of {unit} against its documentation: {reason}":
        "el modelo marcó {dest} de {unit} frente a su documentación: {reason}",
    "it will be cut the first time it is used; accept it if it is legitimate":
        "se cortará la primera vez que se use; acéptalo si es legítimo",
    "its documentation does not explain {dest} of {unit}: review it":
        "su documentación no explica {dest} de {unit}: revísalo",
    "the model compared what it did with its documentation":
        "el modelo contrastó lo que hizo con su documentación",
    "  observation    {observing} services being learned · {watching} watched":
        "  observación    {observing} servicios aprendiendo · {watching} vigilados",
    "a watched service that has restarted since":
        "un servicio vigilado que ya se reinició",
    "library package {lib}, loaded by {unit}, was updated from {old} to {new}":
        "el paquete de librería {lib}, que carga {unit}, se actualizó de {old} a {new}",
    "{unit} loads {lib} {new}, just updated, which cannot be trusted: {reason}":
        "{unit} carga {lib} {new}, recién actualizada, y no es de fiar: {reason}",
    "a signed update below the minimum trust: cutting its network stops a backdoor from calling home without stopping the service":
        "una actualización firmada por debajo de la confianza mínima: cortarle la red impide que una puerta trasera llame a casa sin parar el servicio",
    "confine the service: no outbound network, it keeps running (until you decide)":
        "confinar el servicio: sin red de salida, sigue funcionando (hasta que decidas)",
    "confinement is not possible on this host: decide yourself (arx accept, or stop {unit})":
        "en este host no se puede confinar: decide tú (arx accept, o para {unit})",
    "critical service ({unit}): it is not confined on its own":
        "servicio crítico ({unit}): no se confina solo",
    "invalid service: nothing confined":
        "servicio no válido: no se confina nada",
    "it comes from a verified package and is not a shell, interpreter or downloader: alert only":
        "viene de un paquete verificado y no es una shell, un intérprete ni un descargador: solo se avisa",
    "for a program a service started: accept its whole directory for that service":
        "para un programa que lanzó un servicio: aceptar su directorio entero para ese servicio",
    "for a program a service started: accept also what it starts":
        "para un programa que lanzó un servicio: aceptar también lo que lance",
    " (frozen {ms} ms after it started)":
        " (congelado {ms} ms después de arrancar)",
    "Arx is down: systemd gave up restarting it":
        "Arx está caído: systemd dejó de reiniciarlo",
    "🛑 Arx is down on {host}: systemd gave up restarting it. It will try again every 15 minutes; check: journalctl -u arx":
        "🛑 Arx está caído en {host}: systemd dejó de reiniciarlo. Lo volverá a intentar cada 15 minutos; revisa: journalctl -u arx",
    "report that systemd gave up restarting Arx (systemd runs it)":
        "avisar de que systemd dejó de reiniciar Arx (lo ejecuta systemd)",
    "sshd's configuration could not be read with certainty: alert only, nothing frozen":
        "la configuración de sshd no se pudo leer con certeza: solo se avisa, no se congela nada",
    "Arx's unit {path} was changed or removed":
        "la unit de Arx {path} se cambió o se borró",
    "someone added drop-ins to Arx's unit: {files}":
        "alguien añadió drop-ins a la unit de Arx: {files}",
    "Arx's own files differ from its package: {files}":
        "los ficheros de Arx no coinciden con su paquete: {files}",
    "someone changed Arx itself: it may be an attempt to blind it":
        "alguien ha tocado a Arx: puede ser un intento de dejarlo ciego",
    "Arx stopped: {why}":
        "Arx se detuvo: {why}",
    "⚠ Arx stopped on {host}: {why}. If it wasn't you, someone may be trying to blind it.":
        "⚠ Arx se detuvo en {host}: {why}. Si no fuiste tú, alguien puede estar intentando dejarlo ciego.",
    "log and alert outside the host":
        "registrar y avisar fuera del host",
    "report that Arx was stopped (systemd runs it)":
        "avisar de que Arx se detuvo (lo ejecuta systemd)",
    "could not prepare what {unit} needs to keep authenticating: not confined":
        "no se pudo preparar lo que {unit} necesita para seguir autenticando: no se confina",
    "  process watch: {mode}":
        "  vigilancia de procesos: {mode}",
    "in the kernel, in real time":
        "en el kernel, en tiempo real",
    "each sweep (no kernel connector here)":
        "en cada barrido (aquí no hay conector del kernel)",
    "sshd ran a program before authentication (the xz backdoor pattern)":
        "sshd lanzó un programa antes de autenticar (el patrón de la puerta trasera de xz)",
    "{unit}: sshd, before authenticating anyone, ran {exe}":
        "{unit}: sshd, antes de autenticar a nadie, ejecutó {exe}",
    "a web or database service started a shell or a downloader":
        "un servicio web o de base de datos lanzó una shell o un descargador",
    "{unit} started {exe} as {user}":
        "{unit} lanzó {exe} como {user}",
    "{unit} started {exe}, which it never ran while Arx observed it":
        "{unit} lanzó {exe}, que nunca lanzó mientras Arx lo observaba",
    "a compromised program shows itself by what it starts":
        "un programa comprometido se delata por lo que lanza",
    "isolate that process: no network, and suspended if there are signs of harm":
        "aislar ese proceso: sin red, y congelado si hay señales de daño",
    "a program its service never started: the service keeps running":
        "un programa que su servicio nunca lanzaba: el servicio sigue funcionando",
    "invalid process: nothing contained":
        "proceso no válido: no se contiene nada",
    "pid {pid} ({exe}) without network":
        "pid {pid} ({exe}) sin red",
    "pid {pid} suspended":
        "pid {pid} congelado",
    " · it does not expire, you decide":
        " · no caduca, decides tú",
    "{unit}: {pkg} {version} was just updated; no outbound network while its trust is checked":
        "{unit}: {pkg} {version} se acaba de actualizar; sin red de salida mientras se prueba su confianza",
    "{unit}: {pkg} {version} passed the trust checks; its network is back":
        "{unit}: {pkg} {version} pasó las pruebas de confianza; vuelve a tener red",
    "updater, clock or container service ({unit}): alert only":
        "servicio de actualización, hora o contenedores ({unit}): solo se avisa",
    "the trust checks did not finish in {s} s":
        "las pruebas de confianza no terminaron en {s} s",
    "too many trust checks waiting":
        "demasiadas pruebas de confianza en espera",
    "{pkg} {version} was just updated and {n} services load it: checked first, and cut only if it proves untrusted":
        "{pkg} {version} se acaba de actualizar y la cargan {n} servicios: se prueba primero, y solo se corta si resulta no fiable",
    "the trust checks of {pkg} {version} did not finish and {n} services load it: not cut automatically, review it":
        "las pruebas de confianza de {pkg} {version} no terminaron y la cargan {n} servicios: no se corta solo, revísalo",
    "an update many services load: checked first, cut only with an untrusted verdict":
        "una actualización que cargan muchos servicios: se prueba primero, solo se corta con un veredicto de no fiable",
    "  {n} confined service(s) or program(s) got their network back.":
        "  {n} servicio(s) o programa(s) confinado(s) recuperaron la red.",
    "service marked out-of-bounds":
        "servicio marcado fuera de alcance",
    "accepted by a person for this exact version":
        "aceptada por una persona para esta versión exacta",
    "{unit} tried to reach {ip}:{port}/{proto}, outside its usual behavior: cut":
        "{unit} intentó llegar a {ip}:{port}/{proto}, fuera de su comportamiento habitual: cortado",
    "{unit} reached {ip}:{port}/{proto}, outside its usual behavior: it would be cut with --enforce":
        "{unit} llegó a {ip}:{port}/{proto}, fuera de su comportamiento habitual: con --enforce se cortaría",
    "a program that starts talking somewhere new is how a compromised update calls home":
        "un programa que empieza a hablar con un sitio nuevo es como llama a casa una actualización comprometida",
    "its behavior was still changing at the end of the observation":
        "su comportamiento aún cambiaba al final de la observación",
    "it contacted addresses flagged by intelligence: {ips}":
        "contactó direcciones señaladas por inteligencia: {ips}",
    "it was updated during the observation ({old} → {new})":
        "se actualizó durante la observación ({old} → {new})",
    "observation of {unit} extended: {why}":
        "observación de {unit} alargada: {why}",
    "Arx keeps observing while it has doubts":
        "Arx sigue observando mientras tenga dudas",
    "cut in the kernel at its first packet; the service keeps running":
        "cortado en el kernel desde el primer paquete; el servicio sigue funcionando",
    "outside the behavior Arx observed for it; if it is legitimate, accept it":
        "fuera del comportamiento que Arx le observó; si es legítimo, acéptalo",
    "log and alert":
        "registrar y avisar",
    "requires Linux + root with nftables":
        "requiere Linux + root con nftables",
    "containment back in the kernel: {blocks} · confinements: {confined}":
        "contención repuesta en el kernel: {blocks} · confinamientos: {confined}",
    "nothing was missing":
        "no faltaba nada",
    "put Arx's containment back in the kernel (runs at boot)":
        "reponer en el kernel la contención de Arx (corre al arrancar)",
    "network restored to: {what}":
        "red devuelta a: {what}",
    "confined without outbound network: {what}. It keeps running; it does not expire, you decide":
        "confinado sin red saliente: {what}. Sigue funcionando; no caduca, decides tú",
    "log and alert (verified package)":
        "registrar y avisar (paquete verificado)",
    "confine it: no outbound network, it keeps running (until you decide)":
        "confinarlo: sin red saliente, sigue funcionando (hasta que decidas)",
    "unproven origin and no sign of harm: cutting its network stops a backdoor from calling home without stopping your program":
        "procedencia sin probar y sin señales de daño: cortarle la red impide que una puerta trasera llame a casa sin parar tu programa",
    " (confinement is not possible on this host: suspended instead)":
        " (en este host no se puede confinar: suspendido en su lugar)",
    "{n} confinement(s) put back":
        "{n} confinamiento(s) repuesto(s)",
    " · and {n} new process(es) of the same program":
        " · y {n} proceso(s) nuevo(s) del mismo programa",
    "package {pkg} from a signed repository, intact":
        "paquete {pkg} de un repositorio firmado, intacto",
    "{unit} from package {pkg}, signed repository, intact":
        "{unit} del paquete {pkg}, repositorio firmado, intacto",
    "no package database to check it against":
        "no hay base de paquetes contra la que comprobarlo",
    "it does not belong to any package":
        "no pertenece a ningún paquete",
    "changed since its package installed it":
        "cambió desde que lo instaló su paquete",
    "dpkg has no checksum for it: it cannot be proven intact":
        "dpkg no guarda su resumen: no se puede probar que esté intacto",
    "the process is gone or cannot be read":
        "el proceso ya no existe o no se puede leer",
    "its executable was deleted from disk":
        "su ejecutable se borró del disco",
    "not started by a system service":
        "no lo arranca un servicio del sistema",
    "its unit {unit} is not from any package":
        "su unit {unit} no es de ningún paquete",
    "its unit and its binary come from different packages":
        "su unit y su binario vienen de paquetes distintos",
    "a drop-in changes what {unit} runs: {path}":
        "un drop-in cambia lo que ejecuta {unit}: {path}",
    "runs from a temporary directory":
        "corre desde un directorio temporal",
    "hidden path":
        "ruta oculta",
    "static analysis flagged it":
        "el análisis estático lo marcó",
    "its file was deleted while it runs":
        "su fichero se borró mientras corre",
    "comes from a session the baseline does not know":
        "viene de una sesión que la línea base no conoce",
    "apt does not know this package":
        "apt no conoce este paquete",
    "installed from a local package, not from a repository":
        "instalado desde un paquete suelto, no desde un repositorio",
    "its repository is marked trusted=yes: apt does not check its signature":
        "su repositorio está marcado trusted=yes: apt no comprueba su firma",
    "an interpreter running code that is not from any package":
        "un intérprete que ejecuta código que no es de ningún paquete",
    "started by a network service (webshell pattern)":
        "lo lanzó un servicio de red (patrón de webshell)",
    "no owning process found":
        "no se encontró el proceso dueño",
    "No authorization word: setup cancelled, nothing was saved.":
        "Sin palabra de autorización: configuración cancelada, no se guardó nada.",
    "Arx cannot find a writable directory for its state ({v}). Use ARX_CONFIG_DIR / ARX_STATE_DIR.":
        "Arx no encuentra un directorio escribible para su estado ({v}). Usa ARX_CONFIG_DIR / ARX_STATE_DIR.",
    "Analysis:":
        "Análisis:",
    "empty response":
        "respuesta vacía",
    "the model declined the request":
        "el modelo declinó la petición",
    "no provider responded: ":
        "ningún proveedor respondió — ",
    "{prov}: no key or model":
        "{prov}: sin clave o modelo",
    "unknown provider: {prov}":
        "proveedor desconocido: {prov}",
    "Alert test: if you can read this, Arx can reach you. ✓":
        "Prueba de alertas: si lees esto, Arx puede avisarte. ✓",
    "  findings       {n} known  ·  accept legitimate changes: arx accept":
        "  hallazgos      {n} conocidos  ·  aceptar cambios legítimos: arx accept",
    "  Remediation: {remediation}":
        "  Remediación: {remediation}",
    "  If this was legitimate access, to stop further alerts:  arx accept":
        "  Si es un acceso legítimo, para que no vuelva a avisar:  arx accept",
    "\n▸ Arx license":
        "\n▸ Licencia de Arx",
    "Findings you can accept as normal (they are added to the baseline):":
        "Hallazgos que puedes aceptar como normales (se añaden a la línea base):",
    "\nAccept one with:  arx accept <id>":
        "\nAcepta uno con:  arx accept <id>",
    "No acceptable finding with id '{fp}'. List them:  arx accept":
        "No hay un hallazgo aceptable con id '{fp}'. Lista:  arx accept",
    "No alert channels configured. Run:  arx setup  (step 6)":
        "No hay canales de alerta configurados. Ejecuta:  arx setup  (paso 6)",
    "  baseline       missing  (arx learn)":
        "  baseline       no existe  (arx learn)",
    "  service        (systemd not available here)":
        "  servicio       (systemd no disponible aquí)",
    "  proposals      {n}   ·  review them: arx proposals":
        "  propuestas     {n}   ·  míralas: arx proposals",
    "  locked accts   {v}   ⚠ your call: arx unlock":
        "  cuentas bloq.  {v}   ⚠ decide tú: arx unlock",
    "Pending Tier 2 actions (they need your authorization word):":
        "Acciones Tier 2 pendientes (requieren tu palabra de autorización):",
    "\nAuthorize one with:  arx authorize <id>":
        "\nAutoriza una con:  arx authorize <id>",
    "No pending action with id '{pending_id}'.":
        "No hay ninguna acción pendiente con id '{pending_id}'.",
    "No authorization word configured. Run:  arx setup":
        "No hay palabra de autorización configurada. Ejecuta:  arx setup",
    "Wrong word. Action NOT authorized.":
        "Palabra incorrecta. Acción NO autorizada.",
    "Accounts locked by Arx (they do not unlock on their own):":
        "Cuentas bloqueadas por Arx (no se desbloquean solas):",
    "\nUnlock one with:  arx unlock <account>":
        "\nDesbloquea una con:  arx unlock <cuenta>",
    "Arx has not locked account '{user}'.":
        "Arx no tiene bloqueada la cuenta '{user}'.",
    "Wrong word. The account stays locked.":
        "Palabra incorrecta. La cuenta sigue bloqueada.",
    "⚠ {done}. The account stays locked.":
        "⚠ {done}. La cuenta sigue bloqueada.",
    "Quarantined files (evidence preserved, 0600, root only):":
        "Ficheros en cuarentena (evidencia preservada, 0600, solo root):",
    "\nPut one back with:  arx restore <id>":
        "\nDevuelve uno a su sitio con:  arx restore <id>",
    "Nothing in quarantine with id '{v}'.":
        "No hay nada en cuarentena con id '{v}'.",
    "Wrong word. It stays in quarantine.":
        "Palabra incorrecta. Sigue en cuarentena.",
    "Could not enroll: {reason}":
        "No se pudo enrolar: {reason}",
    "Could not sync: {reason}":
        "No se pudo sincronizar: {reason}",
    "✓ License activated on this server. Tier: {tier} ({why})":
        "✓ Licencia activada en este servidor. Tier: {tier} ({why})",
    "No license: Arx runs as Core (free). Activate with:  arx license activate <KEY>":
        "Sin licencia — Arx opera en Core (gratis). Actívala con:  arx license activate <LLAVE>",
    "  last validated {last_validated_at}":
        "  últ. validación {last_validated_at}",
    "Arx: active and reactive defense":
        "Arx — defensa activa y reactiva",
    "configuration wizard (user side)":
        "wizard de configuración (lado usuario)",
    "show the current configuration (secrets redacted)":
        "mostrar la configuración actual (secretos redactados)",
    "deep initial reconnaissance of the system":
        "reconocimiento inicial profundo del sistema",
    "path of the JSON inventory (default: Arx state dir)":
        "ruta del inventario JSON (por defecto: dir de estado de Arx)",
    "only print to the console, do not write the JSON":
        "solo mostrar en consola, no escribir el JSON",
    "baseline learning window":
        "ventana de aprendizaje de la línea base",
    "number of snapshots to take in this run":
        "nº de instantáneas a integrar en esta corrida",
    "seconds between snapshots":
        "segundos entre instantáneas",
    "seal the baseline (end of learning)":
        "sellar la base (fin del aprendizaje)",
    "show the state of the learned baseline":
        "mostrar el estado de la base aprendida",
    "a single sweep and exit (cron/tests)":
        "un solo barrido y salir (cron/pruebas)",
    "open a console channel with Arx":
        "abrir canal de consola con Arx",
    "show every finding on each sweep":
        "mostrar todos los hallazgos en cada barrido",
    "static analysis of a file (is it malicious?)":
        "análisis estático de un fichero (¿es malicioso?)",
    "path of the file to analyze (it is not executed)":
        "ruta del fichero a analizar (no se ejecuta)",
    "verify the seal of a saved report":
        "verifica el sellado de un informe guardado",
    "only public IPs, hashes and attack types, nothing about this host: safe to share":
        "solo IPs públicas, hashes y tipos de ataque, sin nada de este host: para compartir",
    "overall Arx status (at a glance)":
        "estado general de Arx (un vistazo)",
    "as JSON, for scripts":
        "en JSON, para scripts",
    "view/approve pending Tier 2 actions":
        "ver/aprobar acciones Tier 2 pendientes",
    "id to authorize (no id: list pending)":
        "id a autorizar (sin id: lista los pendientes)",
    "view/unlock accounts locked by Arx":
        "ver/desbloquear cuentas bloqueadas por Arx",
    "account to unlock (no account: list locked)":
        "cuenta a desbloquear (sin cuenta: lista las bloqueadas)",
    "view/put back quarantined files":
        "ver/devolver a su sitio ficheros en cuarentena",
    "file id (no id: list the quarantine)":
        "id del fichero (sin id: lista la cuarentena)",
    "signed vaccines: what other Arx hosts learned":
        "vacunas firmadas: lo que otros Arx aprendieron",
    "show applied and rejected vaccines":
        "ver las aplicadas y las rechazadas",
    "check for new vaccines now":
        "comprobar ahora si hay vacunas nuevas",
    "remove a vaccine from this host":
        "retirar una vacuna de este host",
    "vaccine id":
        "id de la vacuna",
    "what Arx proposes you change (nothing applies on its own)":
        "lo que Arx te propone cambiar (nada se aplica solo)",
    "show the proposals":
        "ver las propuestas",
    "apply a proposal (asks for your word)":
        "aplicar una propuesta (pide tu palabra)",
    "proposal id":
        "id de la propuesta",
    "undo an applied proposal (asks for your word)":
        "deshacer una propuesta aplicada (pide tu palabra)",
    "how much noise Arx makes on this host (false positives)":
        "cuánto ruido hace Arx en este host (falsos positivos)",
    "days to count (default 7)":
        "días a contar (por defecto 7)",
    "numbers only, no paths or names: safe to share":
        "solo cifras, sin rutas ni nombres: se puede compartir",
    "canaries / honeytokens":
        "señuelos / honeytokens",
    "plant canaries (default: homes + /root)":
        "plantar señuelos (por defecto: homes + /root)",
    "where to plant (repeatable)":
        "dónde plantar (repetible)",
    "list active canaries":
        "listar señuelos activos",
    "check canary integrity":
        "verificar integridad de los señuelos",
    "install and start the service":
        "instalar y arrancar el servicio",
    "ExecStart (default: how arx is being invoked now)":
        "ExecStart (por defecto: cómo se invoca arx ahora)",
    "apply automatic Tier 1 actions (default: observe only)":
        "aplicar acciones Tier 1 automáticas (por defecto: solo observar)",
    "remove the service":
        "retirar el servicio",
    "service status":
        "estado del servicio",
    "accept a legitimate change as normal (adds it to the baseline)":
        "aceptar como normal un cambio legítimo (lo añade a la base)",
    "finding id (no id: list acceptable findings)":
        "id del hallazgo (sin id: lista los aceptables)",
    "send a test message through the configured channels":
        "enviar un mensaje de prueba por los canales configurados",
    "enroll this host in the central console":
        "enrolar este host en la consola central",
    "URL of the fleet console":
        "URL de la consola de flota",
    "enrollment token":
        "token de enrolamiento",
    "enrollment status":
        "estado de enrolamiento",
    "send heartbeat + incidents to the console":
        "enviar heartbeat + incidentes a la consola",
    "activate / view / release the license":
        "activar / ver / liberar la licencia",
    "activate a Pro/Business license on this server":
        "activar una licencia Pro/Business en este servidor",
    "the key you bought (Polar)":
        "la llave que compraste (Polar)",
    "show status and effective tier":
        "ver estado y tier efectivo",
    "release the local activation (when reinstalling the server)":
        "liberar la activación local (al reinstalar el servidor)",
    "No baseline findings waiting to be accepted.":
        "No hay hallazgos de línea base pendientes de aceptar.",
    "  {fp}  {detail}   (seen {seen}×, last {v})":
        "  {fp}  {detail}   (visto {seen}×, últ. {v})",
    "   ⚠ SAFETY BRAKE active":
        "   ⚠ FRENO DE SEGURIDAD activo",
    "No pending Tier 2 actions.":
        "No hay acciones Tier 2 pendientes.",
    "Authorization word: ":
        "Palabra de autorización: ",
    "No accounts locked by Arx.":
        "No hay cuentas bloqueadas por Arx.",
    "The quarantine is empty.":
        "La cuarentena está vacía.",
    "  {v}\n      from {v2}  ·  {v3} UTC  ·  sha256 {v4}…":
        "  {v}\n      de {v2}  ·  {v3} UTC  ·  sha256 {v4}…",
    "✓ Host enrolled in the console. agent_id: {agent_id}":
        "✓ Host enrolado en la consola. agent_id: {agent_id}",
    "✓ Synced with the console ({events} incidents sent).":
        "✓ Sincronizado con la consola ({events} incidentes enviados).",
    "Could not activate:":
        "No se pudo activar:",
    "unknown error":
        "error desconocido",
    "✓ Activation released (in Polar and locally). Reinstall and reactivate with the same key.":
        "✓ Activación liberada (en Polar y local). Reinstala y reactiva con la misma llave.",
    "\n▸ Arx: status":
        "\n▸ Arx — estado",
    "  configured     {v}":
        "  configurado    {v}",
    "no  (arx setup)":
        "no  (arx setup)",
    "  license        {tier}  ({why})":
        "  licencia       {tier}  ({why})",
    "  canaries       {n} active, {n2} triggered":
        "  canarios       {n} activos, {n2} disparados",
    "  mode           {v}":
        "  modo           {v}",
    "has not run yet":
        "aún no ha corrido",
    "protect (--enforce)":
        "proteger (--enforce)",
    "observe":
        "observar",
    "  alerts         {v}":
        "  alertas        {v}",
    "none  (arx setup)":
        "ninguna  (arx setup)",
    "  vaccines       {n} applied":
        "  vacunas        {n} aplicadas",
    "✓ Authorized: {detail}":
        "✓ Autorizada: {detail}",
    "  Executed:    {executed}":
        "  Ejecutado:   {executed}",
    "✓ Account '{user}' unlocked: {done}":
        "✓ Cuenta '{user}' desbloqueada: {done}",
    "\n▸ Arx: fleet":
        "\n▸ Arx — flota",
    "  available      {v}":
        "  disponible     {v}",
    "yes (Business)":
        "sí (Business)",
    "no (requires a Business license)":
        "no (requiere licencia Business)",
    "  enrolled       {v}":
        "  enrolado       {v}",
    "yes":
        "sí",
    "  key             {v}":
        "  llave           {v}",
    "  activated       {v}":
        "  activada        {v}",
    "  effective tier  {tier}  ({why})":
        "  tier efectivo   {tier}  ({why})",
    "  providers      {v}":
        "  proveedores    {v}",
    "none":
        "ninguno",
    "  auth word      {v}":
        "  palabra auth   {v}",
    "configured":
        "configurada",
    "  baseline       {estado} ({samples} samples)":
        "  baseline       {estado} ({samples} muestras)",
    "sealed":
        "sellada",
    "learning":
        "aprendiendo",
    "  service        {v}":
        "  servicio       {v}",
    "inactive":
        "inactivo",
    "  T1 blocks      {n} active":
        "  bloqueos T1    {n} activos",
    "  Tier 2 pending {n}":
        "  Tier 2 pend.   {n}",
    "   ⚠ use: arx authorize":
        "   ⚠ usa: arx authorize",
    "  recent incidents:":
        "  incidentes recientes:",
    "  console        {console_url}":
        "  consola        {console_url}",
    "  expires         {expires_at}":
        "  expira          {expires_at}",
    "  {user}  since {v} UTC  ·  {detail}":
        "  {user}  desde {v} UTC  ·  {detail}",
    "operating mode: watch, detect, respond":
        "modo operativo: vigila, detecta, responde",
    "seconds between sweeps":
        "segundos entre barridos",
    "apply Tier 1 remediations (automatic, reversible)":
        "aplicar remediaciones Tier 1 (auto, reversibles)",
    "post-incident forensic report (sealed)":
        "informe forense post-incidente (firmado)",
    "only incidents since this ISO timestamp (UTC)":
        "solo incidentes desde esta marca ISO (UTC)",
    "install/remove Arx as a systemd service (24/7)":
        "instalar/retirar Arx como servicio systemd (24/7)",
    "outgoing alerts (Telegram / webhook)":
        "alertas salientes (Telegram / webhook)",
    "fleet / central console (Business)":
        "flota / consola central (Business)",
    "PATH":
        "RUTA",
    "«redacted»":
        "«redactado»",
    "no previous successful validation → Core":
        "sin validación exitosa previa → Core",
    "Polar did not return an activation_id":
        "Polar no devolvió activation_id",
    "no license activated":
        "sin licencia activada",
    "no license (Core)":
        "sin licencia (Core)",
    "tampered license cache → Core":
        "caché de licencia manipulada → Core",
    "license revoked by the server":
        "licencia revocada por el servidor",
    "rejected by the server (HTTP {http})":
        "rechazada por el servidor (HTTP {http})",
    "grace period over ({age_days} d without validating) → Core":
        "gracia agotada ({age_days} d sin validar) → Core",
    "the console rejected the activation (HTTP {code})":
        "la consola rechazó la activación (HTTP {code})",
    "no connection to Polar: {e}":
        "sin conexión con Polar: {e}",
    "no connection: {e}":
        "sin conexión: {e}",
    "clock anomaly (went backwards): keeping the tier":
        "anomalía de reloj (retroceso) — mantengo el tier",
    "license expired by date":
        "licencia expirada por fecha",
    "valid (validated {v} d ago)":
        "válida (validada hace {v} d)",
    "that key is already in use on another server: release it with 'arx license deactivate' there, or from your Polar portal":
        "esa llave ya está en uso en otro servidor — libérala con 'arx license deactivate' allí, o desde tu portal de Polar",
    "key not recognized: check that you pasted all of it":
        "llave no reconocida — revisa que la pegaste completa",
    "could not release it in Polar ({e}). Release it from your Polar portal.":
        "no se pudo liberar en Polar ({e}). Libérala desde tu portal de Polar.",
    "server {code}":
        "servidor {code}",
    "\n▸ Arx: noise on this host (last {days_covered} days)":
        "\n▸ Arx — ruido en este host (últimos {days_covered} días)",
    "  new findings          {findings_new}":
        "  hallazgos nuevos      {findings_new}",
    "  high or critical      {alerts_high}  ({alerts_high_per_day}/day)":
        "  altos o críticos      {alerts_high}  ({alerts_high_per_day}/día)",
    "  false positives       {false_positives}  ({false_positives_per_day}/day · target < {TARGET_FP_PER_DAY}/day)":
        "  falsos positivos      {false_positives}  ({false_positives_per_day}/día · objetivo < {TARGET_FP_PER_DAY}/día)",
    "  high, unreviewed      {unreviewed_high}":
        "  altos sin revisar     {unreviewed_high}",
    "  within target         {verdict}":
        "  dentro del objetivo   {verdict}",
    "  automatic actions     {automatic_actions}":
        "  acciones automáticas  {automatic_actions}",
    "  accounts locked by the model  {accounts_locked_by_model}":
        "  cuentas que bloqueó el modelo  {accounts_locked_by_model}",
    "\n  A false positive only counts if you mark it (arx accept, arx unlock): whatever you do not review":
        "\n  Un falso positivo solo cuenta si lo marcas (arx accept, arx unlock): lo que no revises",
    "  shows as «unreviewed», not as a hit. To share only the numbers: arx metrics --json\n":
        "  sale como «sin revisar», no como acierto. Para compartir solo las cifras: arx metrics --json\n",
    "Nothing to measure yet: Arx has not recorded any event.":
        "Aún no hay nada que medir: Arx no ha registrado ningún evento.",
    "cannot tell yet: review the alerts":
        "aún no se puede saber: revisa las alertas",
    "systemd unit generated at: {dest}":
        "Unit systemd generado en: {dest}",
    "Unit written, but systemctl failed. Check:  systemctl status arx":
        "Unit escrito, pero systemctl falló. Revisa:  systemctl status arx",
    "This is not a Linux host. On the Ubuntu server:":
        "Este no es un host Linux. En el servidor Ubuntu:",
    "⚠ Prerequisites missing to run 24/7:":
        "⚠ Prerequisitos incompletos para operar 24/7:",
    "  run  setup → recon → learn → learn --seal  before starting the service.":
        "  ejecuta  setup → recon → learn → learn --seal  antes de arrancar el servicio.",
    "  (Without a sealed baseline, guard exits with an error and systemd would retry in a loop.)\n":
        "  (Sin baseline sellada, guard sale con error y systemd reintentaría en bucle.)\n",
    "ℹ OBSERVE mode: Arx detects, logs and alerts, but does not apply Tier 1 actions.\n  Review its findings for a few days (arx status) and, if they are reliable, reinstall with:\n  arx service install --enforce\n":
        "ℹ Modo OBSERVAR: Arx detecta, registra y alerta, pero no aplica acciones Tier 1.\n  Revisa unos días sus hallazgos (arx status) y, si son fiables, reinstala con:\n  arx service install --enforce\n",
    "✓ Arx installed as a systemd service and started (enable --now).":
        "✓ Arx instalado como servicio systemd y arrancado (enable --now).",
    "Requires Linux + root with systemd. On the server:":
        "Requiere Linux + root con systemd. En el servidor:",
    "✓ Arx service removed.":
        "✓ Servicio Arx retirado.",
    "Service status: requires systemd (systemctl). On the server:  systemctl status arx":
        "Estado del servicio: requiere systemd (systemctl). En el servidor:  systemctl status arx",
    "systemd not detected here. On a server with systemd:":
        "systemd no detectado aquí. En un servidor con systemd:",
    "Requires root. Install it with:":
        "Requiere root. Instálalo con:",
    "new in login_users: {item}":
        "nuevo en login_users: {item}",
    "access from an account or origin the baseline does not know":
        "acceso de una cuenta u origen que la línea base no conoce",
    "the authentication log disappeared":
        "el log de autenticación desapareció",
    "deleting the authentication log is anti-forensic: someone is wiping traces":
        "borrar el log de autenticación es anti-forense: alguien borra huellas",
    "account with uid 0 other than root: {name}":
        "cuenta con uid 0 distinta de root: {name}",
    "it has all of root's powers under another name; installed by someone who wants to come back unnoticed. If legitimate, accept it":
        "tiene todos los poderes de root con otro nombre; la instala quien quiere volver a entrar sin que se note. Si es legítima, acéptala",
    "Falco behavior rule fired":
        "regla de comportamiento de Falco disparada",
    "auditd · identity: {line}":
        "auditd · identidad: {line}",
    "write/attribute change on an identity or privilege file":
        "escritura/cambio de atributos en un fichero de identidad o privilegios",
    "canary accessed · {line}":
        "señuelo accedido · {line}",
    "nobody legitimate opens a honeytoken: the access came from the process shown":
        "nadie legítimo abre un honeytoken: el acceso lo hizo el proceso indicado",
    "{path} was truncated (same inode, smaller size)":
        "{path} fue truncado (mismo inode, tamaño menor)",
    "emptying the authentication log is anti-forensic: someone is wiping traces":
        "vaciar el log de autenticación es anti-forense: alguien borra huellas",
    "shell with an outbound connection: {exe} → {ip}:{port} (pid {v})":
        "shell con conexión saliente: {exe} → {ip}:{port} (pid {v})",
    "a shell owning an outbound network socket is the C2 signature of a reverse shell: nobody legitimate does this":
        "un shell que posee un socket de red saliente es la firma del C2 de un reverse shell: nadie legítimo lo hace",
    "{fails} authentication failures from {ip} (most tried user: {user})":
        "{fails} fallos de autenticación desde {ip} (usuario más probado: {user})",
    "brute force against the remote access service":
        "fuerza bruta contra el servicio de acceso remoto",
    "scan from {ip} (≥{SCAN_THRESHOLD} ports in 10 min, kernel trail)":
        "escaneo desde {ip} (≥{SCAN_THRESHOLD} puertos en 10 min, pista kernel)",
    "reconnaissance ahead of an attack: nobody legitimate touches this many ports":
        "reconocimiento previo a un ataque: nadie legítimo toca tantos puertos",
    "scan from {ip} (≥{SCAN_THRESHOLD} accepted ports in 10 min)":
        "escaneo desde {ip} (≥{SCAN_THRESHOLD} puertos aceptados en 10 min)",
    "\n▸ Arx baseline":
        "\n▸ Línea base de Arx",
    "  ⚠ integrity    {n} change(s) in critical files during learning:":
        "  ⚠ integridad   {n} cambio(s) en ficheros críticos durante el aprendizaje:",
    "  integrity      no changes in critical files ✓":
        "  integridad     sin cambios en ficheros críticos ✓",
    "✓ Baseline SEALED with {samples} samples. Ready for `arx guard`.":
        "✓ Línea base SELLADA con {samples} muestras. Lista para `arx guard`.",
    "✓ Backup of {n} critical file(s) in the vault (enables Tier 2 restore).":
        "✓ Respaldo de {n} fichero(s) crítico(s) en el vault (habilita restauración Tier 2).",
    "Once the system has shown its normal behavior, seal the baseline:  arx learn --seal\n":
        "Cuando el sistema haya mostrado su comportamiento normal, sella la base:  arx learn --seal\n",
    "not in the {key} baseline ({n} known)":
        "no aparece en la línea base de {key} ({n} conocidos)",
    "No baseline yet. Run:  arx learn":
        "No hay línea base todavía. Ejecuta:  arx learn",
    "You cannot seal an empty baseline. Run `arx learn` first.":
        "No puedes sellar una base vacía. Ejecuta `arx learn` primero.",
    "✓ nft scan trail active (inet arx: scan4/scan6 + block sets).":
        "✓ Pista de escaneo nft activa (inet arx: scan4/scan6 + sets de bloqueo).",
    "new in {key}: {item}":
        "nuevo en {key}: {item}",
    "{key}={val:.1f} above the learned range [{min:.1f}, {max:.1f}]":
        "{key}={val:.1f} sobre el rango aprendido [{min:.1f}, {max:.1f}]",
    "value outside the learned normal behavior":
        "valor fuera del comportamiento normal aprendido",
    "; it also runs from a temporary directory":
        "; además corre desde un directorio temporal",
    "  samples        {samples}  ·  {v}":
        "  muestras       {samples}  ·  {v}",
    "  created        {created}   updated {updated}":
        "  creada         {created}   actualizada {updated}",
    "✓ {samples} sample(s) taken. Running total: {samples2}.":
        "✓ {samples} muestra(s) integrada(s). Total acumulado: {samples2}.",
    "  {key:<14} {n} known":
        "  {key:<14} {n} conocidos",
    "  {key:<14} range [{min:.1f}, {max:.1f}]  mean {mean:.1f}":
        "  {key:<14} rango [{min:.1f}, {max:.1f}]  media {mean:.1f}",
    "the fleet requires a Business license":
        "la flota requiere licencia Business",
    "the console did not return an agent_id":
        "la consola no devolvió agent_id",
    "not enrolled or no Business license":
        "no enrolado o sin Business",
    "could not reach the console: {e}":
        "no se pudo contactar la consola: {e}",
    "Commands:\n/status · /findings · /pending · /report\n/mute <hours>: silence non-critical alerts\nWith your 6-digit code:\n/authorize <id> <code>\n/unlock <account> <code>\n/accept <id> <code>\n/mode observe|protect <code>\nAny other text goes to the model, if there is one. It cannot act.":
        "Comandos:\n/estado · /hallazgos · /pendientes · /informe\n/callar <horas> — silencia las alertas no críticas\nCon tu código de 6 dígitos:\n/autorizar <id> <código>\n/desbloquear <cuenta> <código>\n/aceptar <id> <código>\n/modo observar|proteger <código>\nCualquier otro texto se lo pregunto al modelo, si lo hay. Él no puede actuar.",
    "Too many failed codes: none accepted for another {v} min.":
        "Demasiados códigos fallidos: no acepto ninguno hasta dentro de {v} min.",
    "Wrong or already used code. Nothing was done.":
        "Código incorrecto o ya usado. No se ha hecho nada.",
    "Arx on guard":
        "Arx en guardia",
    "Arx without a sealed baseline":
        "Arx sin línea base sellada",
    "Mode: {v}":
        "Modo: {v}",
    "protect":
        "proteger",
    "Active blocks: {n}":
        "Bloqueos activos: {n}",
    " · ⚠ BRAKE":
        " · ⚠ FRENO",
    "Waiting on your decision: {n}":
        "Esperan tu decisión: {n}",
    "Locked accounts: ":
        "Cuentas bloqueadas: ",
    "No findings.":
        "Sin hallazgos.",
    "Nothing is waiting on your decision.":
        "Nada espera tu decisión.",
    "Authorize with: /authorize <id> <code>":
        "Autoriza con: /autorizar <id> <código>",
    "Locked account: {user}: /unlock {user} <code>":
        "Cuenta bloqueada: {user} — /desbloquear {user} <código>",
    "Last {days_covered} days: {alerts_high} high or critical alerts, {false_positives} false positives, {unreviewed_high} unreviewed, {automatic_actions} automatic actions.\nActive containment: {active_containment} · in quarantine: {quarantined_evidence}\nThe full sealed forensic report: arx forensics, on the server.":
        "Últimos {days_covered} días: {alerts_high} alertas altas o críticas, {false_positives} falsos positivos, {unreviewed_high} sin revisar, {automatic_actions} acciones automáticas.\nContención activa: {active_containment} · en cuarentena: {quarantined_evidence}\nEl informe forense sellado completo: arx forensics, en el servidor.",
    "Daily summary\n":
        "Resumen del día\n",
    "No model configured. ":
        "Sin modelo configurado. ",
    "The model query budget for today is used up.":
        "Hoy ya se agotó el presupuesto de consultas al modelo.",
    "No model provider responded.":
        "Ningún proveedor del modelo ha respondido.",
    "Usage: /mute <hours>, up to {MAX_MUTE_H}. /mute 0 turns them back on.":
        "Uso: /callar <horas>, hasta {MAX_MUTE_H}. /callar 0 las vuelve a activar.",
    "Non-critical alerts silenced for {hours} h. Critical ones still arrive.":
        "Alertas no críticas silenciadas {hours} h. Las críticas siguen llegando.",
    "Alerts on.":
        "Alertas activas.",
    "I don't know that command. ":
        "No conozco ese comando. ",
    "Usage: {cmd} <{v}> <6-digit code>":
        "Uso: {cmd} <{v}> <código de 6 dígitos>",
    "Authorized: {detail}\n{executed}":
        "Autorizada: {detail}\n{executed}",
    "No pending action with id {target}.":
        "No hay ninguna acción pendiente con id {target}.",
    "Account {target}: {done}":
        "Cuenta {target}: {done}",
    "Arx has not locked account {target}.":
        "Arx no tiene bloqueada la cuenta {target}.",
    "No acceptable finding with id {target}.":
        "No hay un hallazgo aceptable con id {target}.",
    "Usage: /mode observe|protect <code>":
        "Uso: /modo observar|proteger <código>",
    "Mode {target}: applies on the next sweep.":
        "Modo {target}: se aplica en el siguiente barrido.",
    "Could not handle it ({name}).":
        "No pude atenderlo ({name}).",
    "  ⚠ Another program is reading this bot's messages: Telegram stays for outgoing alerts only.":
        "  ⚠ Otro programa lee los mensajes de este bot: Telegram queda solo para alertas salientes.",
    "too long":
        "demasiado larga",
    "backreference":
        "referencia atrás",
    "unbounded quantifier":
        "cuantificador sin límite",
    "construct not allowed":
        "construcción no permitida",
    "quantifier too large":
        "cuantificador demasiado grande",
    "quantifier over a group":
        "cuantificador sobre un grupo",
    "unclosed class":
        "clase sin cerrar",
    "does not compile: {e}":
        "no compila: {e}",
    "no valid identifier":
        "sin identificador válido",
    "no valid version":
        "sin versión válida",
    "description missing or oversized":
        "descripción ausente o desmesurada",
    "unexpected structure":
        "estructura inesperada",
    "more indicators than a vaccine allows":
        "más indicadores de los que admite una vacuna",
    "provides no indicator or rule":
        "no aporta ningún indicador ni regla",
    "invalid IP: {ip}":
        "IP inválida: {ip}",
    "points to a non-public network: {net}":
        "apunta a una red que no es pública: {net}",
    "network too broad: {net}":
        "red demasiado amplia: {net}",
    "invalid sha256":
        "sha256 inválido",
    "malformed rule":
        "regla mal formada",
    "rule {id}: {problem}":
        "regla {id}: {problem}",
    "rule {id}: no proof (samples and negatives are missing)":
        "regla {id}: sin prueba (faltan muestras y negativos)",
    "rule {id}: does not detect its own samples":
        "regla {id}: no detecta sus propias muestras",
    "rule {id}: fires on its negatives":
        "regla {id}: dispara con sus negativos",
    "adds nothing: what it proves was already detected without it":
        "no aporta nada: lo que prueba ya se detectaba sin ella",
    "flags a binary on this host as malicious":
        "marca como malicioso un binario de este host",
    "rule {id}: matches {path} on this host":
        "regla {id}: casa con {path} de este host",
    "passed local validation":
        "superó la validación local",
    "vaccine package too large":
        "paquete de vacunas demasiado grande",
    "disabled in the configuration (vaccines_enabled)":
        "desactivadas en la configuración (vaccines_enabled)",
    "the channel is not open yet: the ASL key is missing":
        "el canal aún no está abierto: falta la clave de ASL",
    "the automatic channel is not open yet":
        "el canal automático aún no está abierto",
    "the automatic channel carries indicators only, not rules":
        "el canal automático solo lleva indicadores, no reglas",
    "more indicators than the automatic channel allows":
        "más indicadores de los que admite el canal automático",
    "network too broad for the automatic channel: {net}":
        "red demasiado amplia para el canal automático: {net}",
    "invalid delegation signature":
        "firma de delegación no válida",
    "malformed delegation":
        "delegación mal formada",
    "delegation longer than {days} days":
        "delegación de más de {days} días",
    "delegation not in force":
        "delegación fuera de vigencia",
    "automatic key revoked by ASL":
        "clave automática revocada por ASL",
    "delegation older than the one in force: possible replay":
        "delegación anterior a la vigente: posible repetición",
    "automatic channel package rejected: {why}":
        "paquete del canal automático rechazado: {why}",
    "vaccine {vid} v{version} validated and applied (automatic channel)":
        "vacuna {vid} v{version} validada y aplicada (canal automático)",
    "no channel right now ({name}); defense carries on the same":
        "sin canal ahora mismo ({name}); la defensa sigue igual",
    "vaccine package with an invalid signature: discarded unopened":
        "paquete de vacunas con firma no válida: descartado sin abrir",
    "invalid signature: discarded unopened":
        "firma no válida: descartado sin abrir",
    "package without a valid serial":
        "paquete sin serial válido",
    "old package (serial {serial} < {serial2}): possible replay":
        "paquete antiguo (serial {serial} < {serial2}): posible repetición",
    "package older than the one applied: possible replay attack":
        "paquete más antiguo que el aplicado: posible ataque de repetición",
    "vaccine {vid} withdrawn by ASL":
        "vacuna {vid} retirada por ASL",
    "vaccine {vid} {status} on this host":
        "vacuna {vid} {status} en este host",
    "vaccine {vid} v{version} validated and applied":
        "vacuna {vid} v{version} validada y aplicada",
    "vaccine update failed ({name})":
        "actualización de vacunas fallida ({name})",
    "its sha256 is that of a known sample (vaccine {vid})":
        "su sha256 es el de una muestra conocida (vacuna {vid})",
    "rule of vaccine {vid}: {v}":
        "regla de la vacuna {vid}: {v}",
    "IP flagged by vaccine {vid}: {ip}":
        "IP señalada por la vacuna {vid}: {ip}",
    "another Arx saw it attack and ASL reviewed it":
        "otro Arx la vio atacar y ASL lo revisó",
    "refuted {FP_ROLLBACK} times":
        "desmentida {FP_ROLLBACK} veces",
    "vaccine {vid} removed: the operator refuted it {FP_ROLLBACK} times":
        "vacuna {vid} retirada: el operador la desmintió {FP_ROLLBACK} veces",
    "removed by the operator":
        "retirada por el operador",
    "vaccine {vid} removed by the operator":
        "vacuna {vid} retirada por el operador",
    "No changes: {reason}":
        "Sin cambios: {reason}",
    "✓ Package {serial}: {n} applied · {n2} rejected · {n3} removed · {n4} waiting":
        "✓ Paquete {serial}: {n} aplicadas · {n2} rechazadas · {n3} retiradas · {n4} en espera",
    "✓ Vaccine {vid} removed. It will not apply again on its own.":
        "✓ Vacuna {vid} retirada. No volverá a aplicarse sola.",
    "No applied vaccine with id '{vid}'.":
        "No hay ninguna vacuna aplicada con id '{vid}'.",
    "\n▸ Arx: vaccines":
        "\n▸ Arx — vacunas",
    "  The channel is not open yet: the ASL public key is missing. Local defense does not depend on it.\n":
        "  El canal aún no está abierto: falta la clave pública de ASL. La defensa local no depende de él.\n",
    "  package        {serial}  ·  issued {v}  ·  last check {v2}":
        "  paquete        {serial}  ·  emitido {v}  ·  última comprobación {v2}",
    "  applied        {n}":
        "  aplicadas      {n}",
    "    {k} v{version}: {n} IPs · {n2} hashes · {n3} rules · {v}":
        "    {k} v{version}: {n} IPs · {n2} hashes · {n3} reglas · {v}",
    "  rejected       {k}: {status}: {reason}":
        "  rechazada      {k}: {status} — {reason}",
    "  removed        {k}: {reason}":
        "  retirada       {k}: {reason}",
    "revert the critical file to a known good copy":
        "revertir el fichero crítico a copia buena conocida",
    "altering credentials or system files is sensitive → needs your word":
        "alterar credenciales/ficheros del sistema es sensible → requiere tu palabra",
    "block the port in the firewall (temporary, auto-expires)":
        "bloquear el puerto en firewall (temporal, auto-expira)",
    "blocking a port is reversible and contains new exposure":
        "bloquear un puerto es reversible y contiene exposición nueva",
    "suspend the process (SIGSTOP) for analysis":
        "suspender el proceso (SIGSTOP) para análisis",
    "suspending is reversible (SIGCONT); it does not destroy evidence":
        "suspender es reversible (SIGCONT); no destruye evidencia",
    "lock all access for the account and close its sessions (it does not unlock on its own)":
        "bloquear todos los accesos de la cuenta y cerrar sus sesiones (no se desbloquea sola)",
    "a new connected account may be a legitimate admin → needs your word or the model confirming it as a threat; a closed session cannot be recovered, and root and system accounts are never touched":
        "una cuenta nueva conectada puede ser un admin legítimo → requiere tu palabra o que el modelo la confirme como amenaza; una sesión cerrada no se puede recuperar y jamás se toca root ni cuentas de sistema",
    "remove its SUID bit (chmod u-s); the file stays as evidence":
        "quitarle el bit SUID (chmod u-s); el fichero se queda como evidencia",
    "a new SUID gives root to whoever runs it, but it may come from a package → needs your word":
        "un SUID nuevo da root a quien lo ejecute, pero puede venir de un paquete → requiere tu palabra",
    "lock that account (password and SSH key); root is not affected":
        "bloquear esa cuenta (contraseña y llave SSH); no afecta a root",
    "it may be legitimate → needs your word; if it is, accept it with arx accept":
        "puede ser legítima → requiere tu palabra; si lo es, acéptala con arx accept",
    "raise the alert level and capture the context of the canary access":
        "elevar el nivel de alerta y capturar el contexto del acceso al señuelo",
    "a touched canary is a strong sign of an intruder; raising and capturing is reversible":
        "un señuelo tocado es señal fuerte de intruso; elevar y capturar es reversible",
    "block the IP in the firewall (temporary, auto-expires)":
        "bloquear la IP en el firewall (temporal, auto-expira)",
    "it comes from a vaccine validated on this host: blocking it is reversible":
        "viene de una vacuna validada en este host: bloquearla es reversible",
    "block the source IP in the firewall (temporary, auto-expires)":
        "bloquear la IP de origen en el firewall (temporal, auto-expira)",
    "cutting reconnaissance is reversible and touches nothing local":
        "cortar el reconocimiento es reversible y no toca nada local",
    "stops the brute force without touching the attacked account (that is Tier 2)":
        "corta la fuerza bruta sin tocar la cuenta atacada (eso es Tier 2)",
    "block the C2 channel in nftables and suspend the owning process (auto-expires)":
        "bloquear el canal C2 en nftables y suspender el proceso dueño (auto-expira)",
    "both actions undo themselves on expiry: no evidence destroyed, no flow lost":
        "ambas acciones se deshacen al expirar: ni se destruye evidencia ni se pierde el flujo",
    "log and alert: someone is wiping traces":
        "registrar y alertar — alguien está borrando huellas",
    "wiping logs is a sign of an intruder INSIDE: observe and escalate, do not act blindly":
        "borrar logs es señal de intruso DENTRO: observar y escalar, no actuar a ciegas",
    "log and watch the trend":
        "registrar y vigilar la tendencia",
    "weak signal; observe first":
        "señal débil; observar primero",
    "log and alert: active containment was already put back":
        "registrar y alertar: la contención activa ya se repuso",
    "it may be a legitimate reboot: your call":
        "puede ser un reinicio legítimo: lo decides tú",
    "log and watch (local-only port)":
        "registrar y vigilar (puerto solo local)",
    "not exposed to the network: a block would contain nothing":
        "no está expuesto a la red: un bloqueo no contendría nada",
    "log and watch (new system binary)":
        "registrar y vigilar (binario de sistema nuevo)",
    "low-confidence signal: it does not justify suspending anything":
        "señal de baja confianza: no justifica suspender nada",
    "log and watch":
        "registrar y vigilar",
    "(none)":
        "(ninguno)",
    "SSH port: blocking it would lock you out of the server":
        "puerto SSH: bloquearlo te dejaría fuera del servidor",
    "port marked out-of-bounds":
        "puerto marcado fuera-de-límites",
    "untouchable IP (the host's own or with an active operator session)":
        "IP intocable (propia del host o con sesión de operador activa)",
    "IP marked out-of-bounds":
        "IP marcada fuera-de-límites",
    "the peer is untouchable (the host's own or an operator session)":
        "la contraparte es intocable (propia del host o sesión de operador)",
    "critical process ({base}): observed only":
        "proceso crítico ({base}): solo se observa",
    "critical process ({base})":
        "proceso crítico ({base})",
    "process marked out-of-bounds":
        "proceso marcado fuera-de-límites",
    "path marked out-of-bounds":
        "ruta marcada fuera-de-límites",
    "SIGCONT to {done} process(es) of {exe}":
        "SIGCONT a {done} proceso(s) de {exe}",
    "account '{user}' was recreated with another uid: not unlocked":
        "cuenta '{user}' recreada con otro uid: no se desbloquea",
    "account '{user}' no longer exists: nothing to unlock":
        "cuenta '{user}' ya no existe: nada que desbloquear",
    "could not restore account '{user}': usermod did not respond":
        "no se pudo restaurar la cuenta '{user}': usermod no respondió",
    "could not restore account '{user}' ({v})":
        "no se pudo restaurar la cuenta '{user}' ({v})",
    "{argv} (previous account state restored)":
        "{argv} (estado previo de la cuenta restaurado)",
    "until you decide":
        "hasta que lo decidas",
    "until {v} UTC":
        "hasta {v} UTC",
    "{dest} already exists: not overwritten. Move it first if you want this one back":
        "ya existe {dest}: no se pisa. Muévelo antes si quieres recuperar este",
    "could not restore {dest} ({strerror})":
        "no se pudo restaurar {dest} ({strerror})",
    "restored to {dest}":
        "restaurado en {dest}",
    "no resolved executable path: nothing is killed by name":
        "sin ruta de ejecutable resuelta: no se mata por nombre",
    "critical process ({base}): never killed":
        "proceso crítico ({base}): jamás se mata",
    "lives in a system directory: the file is not touched":
        "vive en un directorio del sistema: el fichero no se toca",
    "file quarantined (recover it with: arx restore {q})":
        "fichero en cuarentena (recupéralo con: arx restore {q})",
    "the file could not be quarantined":
        "el fichero no se pudo poner en cuarentena",
    "no process left alive":
        "no quedaba ningún proceso vivo",
    "{killed} process(es) terminated":
        "{killed} proceso(s) terminado(s)",
    "could not open {path} ({strerror})":
        "no se pudo abrir {path} ({strerror})",
    "{path} is no longer a regular file: not touched":
        "{path} ya no es un fichero normal: no se toca",
    "could not change {path} ({strerror})":
        "no se pudo cambiar {path} ({strerror})",
    "SUID bit removed from {path}: it no longer gives privileges. If it was legitimate: chmod u+s":
        "bit SUID retirado de {path}: ya no da privilegios. Si era legítimo: chmod u+s",
    "no backup in the vault for '{key}': manual restore needed":
        "sin respaldo en el vault para '{key}' — restauración manual necesaria",
    "'{key}' already matches the sealed version: nothing to restore":
        "'{key}' ya coincide con el sellado — nada que restaurar",
    "restored {n} file(s) of '{key}' from the vault; hostile versions quarantined: {n2}":
        "restaurado {n} fichero(s) de '{key}' desde el vault; versiones hostiles en cuarentena: {n2}",
    "invalid account name ({user}): not locked":
        "nombre de cuenta inválido ({user}): no se bloquea",
    "account '{user}' no longer exists: nothing to lock":
        "la cuenta '{user}' ya no existe: nada que bloquear",
    "system account ({user}, uid {uid}): never locked automatically":
        "cuenta de sistema ({user}, uid {uid}): jamás se bloquea automáticamente",
    "account '{user}' marked out-of-bounds: not locked":
        "cuenta '{user}' marcada fuera-de-límites: no se bloquea",
    "no usermod on this host: no safe account-lock executor":
        "sin usermod en este host: no hay ejecutor seguro de bloqueo de cuenta",
    "account '{user}' was already locked by Arx. Your call:  arx unlock {user}":
        "la cuenta '{user}' ya estaba bloqueada por Arx. Decide tú:  arx unlock {user}",
    "could not read the state of '{user}' in /etc/shadow: not locked":
        "no pude leer el estado de '{user}' en /etc/shadow: no se bloquea",
    "'{user}' is the last admin account with access: locking it would lock you out of the server. Not locked":
        "'{user}' es la última cuenta de administración con acceso: bloquearla te dejaría fuera del servidor. No se bloquea",
    "could not lock the account ({v})":
        "no se pudo bloquear la cuenta ({v})",
    "account '{user}' locked: no entry by password or SSH key. It does not unlock on its own: your call with  arx unlock {user}":
        "cuenta '{user}' bloqueada: no entra ni con contraseña ni con llave SSH. No se desbloquea sola: decide tú con  arx unlock {user}",
    "origin of locked account {user}: {origin}":
        "origen de la cuenta bloqueada {user}: {origin}",
    "its IP {origin} is not blocked: {reason}":
        "su IP {origin} no se bloquea: {reason}",
    "Account '{user}': ":
        "Cuenta '{user}': ",
    "ALL ACCESS CLOSED":
        "TODOS SUS ACCESOS CERRADOS",
    "no action taken":
        "no se actuó",
    "  Detected: {detail}":
        "  Detectado: {detail}",
    "  Decided by: {decided_by}":
        "  Decidió: {decided_by}",
    "  Model verdict: {verdict} ({confidence}%). {reason}":
        "  Veredicto del modelo: {verdict} ({confidence}%). {reason}",
    "  Sessions and processes closed: {n}. A closed session cannot be recovered.":
        "  Sesiones y procesos cerrados: {n}. Una sesión cerrada no se puede recuperar.",
    "    · and {v} more (arx forensics)":
        "    · y {v} más (arx forensics)",
    "  ⚠ STILL ALIVE: {v}. Check them by hand.":
        "  ⚠ SIGUEN VIVOS: {v}. Revísalos a mano.",
    "  This does not cover what does not go through the account: API tokens, keys stolen from other services, or persistence already installed as root.":
        "  No cubre lo que no pasa por la cuenta: tokens de API, claves robadas de otros servicios o persistencia ya instalada como root.",
    "  Your call:  arx unlock {user}   ·   if it was legitimate, then:  arx accept":
        "  Decide tú:  arx unlock {user}   ·   si era legítima, después:  arx accept",
    "observe mode: with --enforce its access would have been closed":
        "modo observar: con --enforce se habrían cerrado sus accesos",
    "disabled in the configuration (llm_identity_actions)":
        "desactivado en la configuración (llm_identity_actions)",
    "you already unlocked it: the model does not overrule you":
        "ya la desbloqueaste tú: el modelo no te lleva la contraria",
    "no verifiable live session from that origin (auth.log can be forged)":
        "sin sesión viva comprobable desde ese origen (auth.log se puede falsificar)",
    "it already locked {MAX_LLM_LOCKS_PER_HOUR} accounts in an hour: it may be manipulated":
        "ya bloqueó {MAX_LLM_LOCKS_PER_HOUR} cuentas en una hora: puede estar manipulado",
    "the model, without waiting for your word (--enforce allows it)":
        "el modelo, sin esperar tu palabra (lo permite --enforce)",
    "\n  Still waiting on you:  arx authorize {v}":
        "\n  Sigue pendiente de ti:  arx authorize {v}",
    "locked by model verdict → your call: arx unlock {user}":
        "bloqueada por veredicto del modelo → decide tú: arx unlock {user}",
    "ready to run on the target":
        "listo para ejecutar en destino",
    "account '{user}' unlocked by human decision":
        "cuenta '{user}' desbloqueada por decisión humana",
    "ready to run on the target (requires Linux + root)":
        "listo para ejecutar en destino (requiere Linux + root)",
    "you, with your authorization word":
        "tú, con tu palabra de autorización",
    "protected ({reason}): no action taken":
        "protegido ({reason}): no se actúa",
    ". Its open sessions are NOT closed: they share a uid with root. Find them with `who` and close them by hand":
        ". Sus sesiones abiertas NO se cierran: comparten uid con root. Búscalas con `who` y ciérralas a mano",
    "plan logged: no Tier 2 executor yet for this type":
        "plan registrado — aún sin ejecutor Tier 2 para este tipo",
    "Could not update the baseline (does it exist and contain that set?).":
        "No se pudo actualizar la línea base (¿existe y contiene ese conjunto?).",
    "  ·  its block has been lifted":
        "  ·  su bloqueo se ha levantado",
    "✓ Accepted as normal: {item}":
        "✓ Aceptado como normal: {item}",
    "⚠ Vaccine {vaccine} removed: you have refuted it several times.":
        "⚠ Vacuna {vaccine} retirada: la has desmentido varias veces.",
    "⚠ That account stays locked: accepting does not unlock it. Use:  arx unlock":
        "⚠ Esa cuenta sigue bloqueada: aceptar no la desbloquea. Usa:  arx unlock",
    "the firewall was emptied (reboot or flush): {restored} of {missing} blocks put back":
        "el firewall se vació (reinicio o flush): {restored} de {missing} bloqueos repuestos",
    "a reboot explains it; if you did not reboot, someone with root deleted Arx's rules":
        "un reinicio lo explica; si no reiniciaste, alguien con root borró las reglas de Arx",
    "nftables present but the arx table could not be prepared":
        "nftables presente pero no se pudo preparar la tabla arx",
    "port {port}/{proto} blocked in nftables (native timeout {DEFAULT_TTL_MIN} min + Arx revert)":
        "puerto {port}/{proto} bloqueado en nftables (timeout nativo {DEFAULT_TTL_MIN} min + reversión de Arx)",
    "nft failed to block ({v})":
        "nft falló al bloquear ({v})",
    "ufw already has a rule for port {port}: not touched (blocking would destroy it). Install nftables to cut it without touching your rules":
        "ufw ya tiene una regla para el puerto {port}: no se toca (bloquear la destruiría). Instala nftables para cortar sin tocar tus reglas",
    "port {port}/{proto} blocked in ufw (auto-expires in {DEFAULT_TTL_MIN} min)":
        "puerto {port}/{proto} bloqueado en ufw (auto-expira en {DEFAULT_TTL_MIN} min)",
    "could not block the port ({v})":
        "no se pudo bloquear el puerto ({v})",
    "ufw is INACTIVE: a block would have no effect (enable it or decide yourself)":
        "ufw está INACTIVO: un bloqueo no tendría efecto (actívalo o decide tú)",
    "no ufw or nftables: no safe block executor on this host":
        "sin ufw ni nftables: no hay ejecutor seguro de bloqueo en este host",
    "no resolved executable path: nothing is suspended by name":
        "sin ruta de ejecutable resuelta: no se suspende por nombre",
    "critical process ({base}): never suspended":
        "proceso crítico ({base}): jamás se suspende",
    "the process is no longer alive: nothing to suspend":
        "el proceso ya no está vivo: nada que suspender",
    "could not suspend (race or permissions)":
        "no se pudo suspender (carrera o permisos)",
    "process suspended ({stopped} pid): automatic SIGCONT on expiry ({DEFAULT_TTL_MIN} min)":
        "proceso suspendido ({stopped} pid) — SIGCONT automático al expirar ({DEFAULT_TTL_MIN} min)",
    "alert level raised and context captured":
        "nivel de alerta elevado y contexto capturado",
    "invalid IP ({ip}): not blocked":
        "IP inválida ({ip}): no se bloquea",
    "IP {ip} THROTTLED in nftables (per-IP rate limit ~2 conn/s and ~50 pkt/s; auto-expires in {DEFAULT_TTL_MIN} min)":
        "IP {ip} ESTRANGULADA en nftables (rate-limit per-IP ~2 conx/s y ~50 paq/s; auto-expira en {DEFAULT_TTL_MIN} min)",
    "nft failed to throttle the IP ({v})":
        "nft falló al estrangular la IP ({v})",
    "IP {ip} blocked in nftables (native timeout {DEFAULT_TTL_MIN} min + Arx revert)":
        "IP {ip} bloqueada en nftables (timeout nativo {DEFAULT_TTL_MIN} min + reversión de Arx)",
    "nft failed to block the IP ({v})":
        "nft falló al bloquear la IP ({v})",
    "IP {ip} blocked in ufw, for new connections only: those already open stay up (install nftables to cut them). Auto-expires in {DEFAULT_TTL_MIN} min":
        "IP {ip} bloqueada en ufw, solo para conexiones nuevas: las ya abiertas siguen (instala nftables para cortarlas). Auto-expira en {DEFAULT_TTL_MIN} min",
    "could not block the IP ({v})":
        "no se pudo bloquear la IP ({v})",
    "invalid IP ({ip}): no action taken":
        "IP inválida ({ip}): no se actúa",
    "C2 channel cut in nftables ({ip}:{port})":
        "canal C2 cortado en nftables ({ip}:{port})",
    "the C2 channel IS STILL OPEN (no usable nftables)":
        "el canal C2 SIGUE ABIERTO (sin nftables utilizable)",
    "owning process suspended ({n} pid)":
        "proceso dueño suspendido ({n} pid)",
    "no live process to suspend":
        "sin proceso vivo que suspender",
    ": undoes itself in {DEFAULT_TTL_MIN} min":
        " — se deshace solo en {DEFAULT_TTL_MIN} min",
    "proposal (no safe automatic executor for this type)":
        "propuesta (sin ejecutor automático seguro para este tipo)",
    "observed and logged":
        "observado y registrado",
    "protected ({reason}): observed only":
        "protegido ({reason}) — solo se observa",
    "already contained (active block {blk})":
        "ya contenido (bloqueo activo {blk})",
    "{action}: REAPPEARED after the block expired":
        "{action} — REAPARECIÓ tras expirar el bloqueo",
    "reappeared after the block expired → your call: arx authorize {pid}  ·  or accept: arx accept {fp}":
        "reapareció tras expirar el bloqueo → decide tú: arx authorize {pid}  ·  o acepta: arx accept {fp}",
    "automatic proposal: enable --enforce to apply":
        "propuesta auto — activa --enforce para aplicar",
    "SAFETY BRAKE: already {MAX_TIER1_PER_HOUR} automatic actions in the last hour → observing only":
        "FRENO DE SEGURIDAD: ya hubo {MAX_TIER1_PER_HOUR} acciones automáticas en la última hora → solo observo",
    " · if legitimate:  arx accept {fp}":
        " · si es legítimo:  arx accept {fp}",
    "already authorized and active {blk}":
        "ya autorizado y activo {blk}",
    "you unlocked it: observed only (make it normal with: arx accept {fp})":
        "la desbloqueaste tú: solo se observa (hazla normal con: arx accept {fp})",
    "authorized by word ✓":
        "autorizada por palabra ✓",
    "PENDING (id {pid}): authorize with: arx authorize {pid}":
        "PENDIENTE (id {pid}) — autoriza con: arx authorize {pid}",
    "chain intact and HMAC valid":
        "cadena íntegra y HMAC válido",
    "Incidents: {incidents} · max severity: {v} · actions: {actions_taken} · quarantine: {quarantined_evidence}":
        "Incidentes: {incidents} · severidad máx: {v} · acciones: {actions_taken} · cuarentena: {quarantined_evidence}",
    "\n▸ Timeline":
        "\n▸ Cronología",
    "▸ Report saved to: {dest}  (verify it with: arx forensics --verify {dest})\n":
        "▸ Informe guardado en: {dest}  (verifícalo con: arx forensics --verify {dest})\n",
    "malformed report: the seal is missing or it lacks the expected structure":
        "informe mal formado: falta el sello o no tiene la estructura esperada",
    "the hash chain does not match: the timeline was altered":
        "la cadena de hash no cuadra: la cronología fue alterada",
    "this host does not have the sealing key: it cannot be verified here":
        "este host no tiene la clave de sellado: no se puede verificar aquí",
    "signed with another key (another host or a rotated key)":
        "firmado con otra clave (otro host o clave rotada)",
    "the HMAC does not match: the report was altered or re-signed without the key":
        "el HMAC no cuadra: el informe fue alterado o re-firmado sin la clave",
    "  (no incidents recorded in the window)":
        "  (sin incidentes registrados en la ventana)",
    "\n▸ Containment still active":
        "\n▸ Contención aún activa",
    "Could not read a report at {verify_path}":
        "No pude leer un informe en {verify_path}",
    "\n══ Forensic report {id} · {generated} ══":
        "\n══ Informe forense {id} · {generated} ══",
    "\n▸ Seal  chain={v}…  key_id={key_id}  → {msg}":
        "\n▸ Sellado  cadena={v}…  key_id={key_id}  → {msg}",
    "Window: {since} → {until}":
        "Ventana: {since} → {until}",
    "\n▸ Preserved evidence (quarantine)":
        "\n▸ Evidencia preservada (cuarentena)",
    "EICAR test file (antivirus standard)":
        "fichero de prueba EICAR (estándar antivirus)",
    "reverse shell via bash /dev/tcp":
        "reverse shell por /dev/tcp de bash",
    "netcat that runs a shell on connect":
        "netcat que ejecuta un shell al conectar",
    "reverse shell with FIFO and netcat":
        "reverse shell con FIFO y netcat",
    "Python reverse shell (socket with dup2 or a shell, or pty.spawn)":
        "reverse shell en Python (socket con dup2 o un shell, o pty.spawn)",
    "Perl reverse shell (socket with exec of a shell)":
        "reverse shell en Perl (socket con exec de un shell)",
    "PHP reverse shell (fsockopen running a shell)":
        "reverse shell en PHP (fsockopen con ejecución de un shell)",
    "download piped straight into a shell (curl|sh)":
        "descarga tubería directa a un shell (curl|sh)",
    "base64 payload run by a shell":
        "payload en base64 ejecutado por un shell",
    "cryptocurrency miner indicators":
        "indicadores de minero de criptomoneda",
    "executable with very high entropy (packed/encrypted)":
        "ejecutable con entropía muy alta (empaquetado/cifrado)",
    "empty":
        "vacío",
    "text":
        "texto",
    "data":
        "datos",
    "{why} · static analysis: {verdict}":
        "{why} · análisis estático: {verdict}",
    "\n▸ Static analysis · {v}":
        "\n▸ Análisis estático · {v}",
    "  type       {type}{shebang}":
        "  tipo       {type}{shebang}",
    "not computed":
        "no calculado",
    "  size       {v} B":
        "  tamaño     {v} B",
    "  (partial analysis)":
        "  (análisis parcial)",
    "  entropy    {entropy} bits/byte":
        "  entropía   {entropy} bits/byte",
    "  verdict    {v}":
        "  veredicto  {v}",
    "  matched rules:":
        "  reglas que casaron:",
    "  (no rule matched; no static malware indicators)":
        "  (ninguna regla casó; sin indicadores estáticos de malware)",
    "no indicators, but only {v} of {total} B were analyzed":
        "sin indicadores, pero solo se analizaron {v} de {total} B",
    "the analysis ran out of its {budget:g} s budget (possible trap file)":
        "el análisis agotó su presupuesto de {budget:g} s (posible fichero trampa)",
    "unnamed or duplicate rule: {rid}":
        "regla sin nombre o duplicada: {rid}",
    "{rid}: invalid severity {sev}":
        "{rid}: severidad inválida {sev}",
    "{rid}: substr needs 'needle' as bytes":
        "{rid}: substr necesita 'needle' en bytes",
    "not a regular file: not read":
        "no es un fichero regular: no se lee",
    "unreadable: {e}":
        "ilegible: {e}",
    "{rid}: entropy needs a numeric 'min_entropy'":
        "{rid}: entropy necesita 'min_entropy' numérico",
    "{rid}: invalid regex":
        "{rid}: regex inválida",
    "{rid}: unknown matcher type {t}":
        "{rid}: tipo de matcher desconocido {t}",
    "\n▸ Arx configuration":
        "\n▸ Configuración de Arx",
    "  fallback order {v}":
        "  orden fallback {v}",
    "  {prov:<12} model {model}  ·  key {v}":
        "  {prov:<12} modelo {model}  ·  clave {v}",
    "NOT configured":
        "NO configurada",
    "  scope          {scope}":
        "  alcance        {scope}",
    "(the whole host)":
        "(todo el host)",
    "  out-of-bounds  {out_of_bounds}":
        "  fuera-límites  {out_of_bounds}",
    "  baseline       {baseline_days} days":
        "  baseline       {baseline_days} días",
    "  LLM            only on new findings · max {llm_daily_budget}/day":
        "  LLM            solo ante hallazgos nuevos · máx {llm_daily_budget}/día",
    "  alerts         telegram {tg} · webhook {v} · from sev {min_sev}":
        "  alertas        telegram {tg} · webhook {v} · desde sev {min_sev}",
    "  chat control   {v}":
        "  gobierno chat  {v}",
    "yes, with a one-time code":
        "sí, con código de un solo uso",
    "  on a scan      {ip_response}":
        "  ante escaneo   {ip_response}",
    "  model locks    {v} · from {llm_lock_min_confidence}% confidence":
        "  modelo bloquea {v} · desde {llm_lock_min_confidence}% de confianza",
    "yes, with --enforce":
        "sí, con --enforce",
    "  license        {license_tier}\n":
        "  licencia       {license_tier}\n",
    "\n═ Arx · configuration ═":
        "\n═ Arx · configuración ═",
    "\n1) LLM providers  (Enter on the key = skip that provider)":
        "\n1) Proveedores LLM  (Enter en la clave = omitir ese proveedor)",
    "   API key for {prov} (empty = skip)":
        "   Clave API de {prov} (vacío = omitir)",
    "   Model for {prov}":
        "   Modelo de {prov}",
    "   ⚠ No providers: Arx cannot reason until you configure at least one.":
        "   ⚠ Sin proveedores: Arx no podrá razonar hasta que configures al menos uno.",
    "\n2) Authorization word  (for irreversible actions · Tier 2)":
        "\n2) Palabra de autorización  (para acciones irreversibles · Tier 2)",
    "   Word":
        "   Palabra",
    "   It cannot be empty.":
        "   No puede quedar vacía.",
    "   Repeat the word":
        "   Repite la palabra",
    "   They do not match, try again.":
        "   No coinciden, reintenta.",
    "\n3) Scope":
        "\n3) Alcance",
    "   What Arx defends":
        "   Qué defiende Arx",
    "the whole host":
        "todo el host",
    "   Out of bounds: ports, paths, processes or accounts it must NEVER touch, comma-separated (the SSH port is already protected)":
        "   Fuera de límites — puertos, rutas, procesos o cuentas que NUNCA debe tocar, separados por coma (el puerto SSH ya está protegido)",
    "\n4) Learning and engine":
        "\n4) Aprendizaje y motor",
    "   Baseline window in days":
        "   Días de ventana de baseline",
    "   Maximum LLM queries per day (only used on new findings)":
        "   Máximo de consultas al LLM por día (solo se usa ante hallazgos nuevos)",
    "\n5) License":
        "\n5) Licencia",
    "   License key (Enter to activate later)":
        "   Clave de licencia (Enter para activar más tarde)",
    "   ✓ License activated on this server · tier {et}":
        "   ✓ Licencia activada en este servidor · tier {et}",
    "   ⚠ Could not activate now ({reason}). Saved; retry:  arx license activate <KEY>":
        "   ⚠ No pude activar ahora ({reason}). Guardada; reintenta:  arx license activate <LLAVE>",
    "   ⚠ No connection to activate ({e}). Saved; retry:  arx license activate <KEY>":
        "   ⚠ Sin conexión para activar ({e}). Guardada; reintenta:  arx license activate <LLAVE>",
    "\n6) Alerts  (Enter = skip)":
        "\n6) Alertas  (Enter = omitir)",
    "   Telegram: in the app, talk to @BotFather, send it /newbot and follow its steps. It will give you a token.\n   Create a bot just for Arx: it is yours, and nobody but you goes through it.":
        "   Telegram: en la app, habla con @BotFather, envíale /newbot y sigue sus pasos. Te dará un token.\n   Crea un bot solo para Arx: es tuyo, y nadie más que tú pasa por él.",
    "   Telegram bot token (empty = keep/skip)":
        "   Token del bot de Telegram (vacío = mantener/omitir)",
    "   ✓ Bot @{name}. Send it any message from your phone now (waiting 90 s)…":
        "   ✓ Bot @{name}. Envíale ahora cualquier mensaje desde tu móvil (espero 90 s)…",
    "   ✓ Your chat is {chat}. Only this chat can talk to Arx.":
        "   ✓ Tu chat es el {chat}. Solo este chat podrá hablar con Arx.",
    "   No message arrived: type the chat_id by hand.":
        "   No llegó ningún mensaje: escribe el chat_id a mano.",
    "   ⚠ Could not check that token now (is it right? is there a connection?). Saving it anyway.":
        "   ⚠ No pude comprobar ese token ahora (¿es correcto? ¿hay conexión?). Se guarda igualmente.",
    "   Telegram chat_id to alert":
        "   chat_id de Telegram al que avisar",
    "   Control Arx from that chat? (query, and authorize with a one-time code) (y/n)":
        "   ¿Gobernar Arx desde ese chat? (consultar, y autorizar con código de un solo uso) (s/n)",
    "   Add this key to your authenticator app (Google Authenticator, Aegis, 1Password…):":
        "   Añade esta clave a tu app de autenticación (Google Authenticator, Aegis, 1Password…):",
    "   This is what Arx will ask for to act from the chat: your word never travels through it.":
        "   Es lo que te pedirá Arx para actuar desde el chat: tu palabra nunca viaja por él.",
    "   Webhook URL (Slack/Discord/n8n…)":
        "   URL de webhook (Slack/Discord/n8n…)",
    "   Alert from severity (crit/high/med)":
        "   Avisar desde severidad (crit/high/med)",
    "\n7) Automatic response  (only acts with --enforce)":
        "\n7) Respuesta automática  (solo actúa con --enforce)",
    "   On a scan: block (cut the IP) or tarpit (throttle it: useful if the IP may be shared)":
        "   Ante un escaneo: block (cortar la IP) o tarpit (estrangularla: útil si la IP puede ser compartida)",
    "   If the model confirms unknown access as a threat, Arx can lock that account and\n   close its sessions without waiting for you, and alerts you with the full context. It never touches root,\n   system accounts or the last admin account.":
        "   Si el modelo confirma como amenaza un acceso desconocido, Arx puede bloquear esa cuenta y\n   cerrar sus sesiones sin esperarte, y te avisa con todo el contexto. Nunca toca root,\n   cuentas de sistema ni la última cuenta de administración.",
    "   Allow it? (y/n)":
        "   ¿Permitirlo? (s/n)",
    "\n✓ Configuration saved:":
        "\n✓ Configuración guardada:",
    "\nNext step:  arx recon\n":
        "\nSiguiente paso:  arx recon\n",
    "Arx is not configured yet. Run:  arx setup":
        "Arx no está configurado todavía. Ejecuta:  arx setup",
    "Arx · chat  (type 'exit' to finish)":
        "Arx · chat  (escribe 'salir' para terminar)",
    "▸ Arx on guard  ·  tier {tier} ({why})":
        "▸ Arx en guardia  ·  tier {tier} ({why})",
    "  sensors: {active}  ·  enforce={v}  ·  {v2}":
        "  sensores: {active}  ·  enforce={v}  ·  {v2}",
    "one sweep":
        "un barrido",
    "every {interval}s":
        "cada {interval}s",
    "  alerts: {v}  ·  LLM: only on new findings (max {llm_daily_budget}/day)":
        "  alertas: {v}  ·  LLM: solo ante hallazgos nuevos (máx {llm_daily_budget}/día)",
    "none (configure them in arx setup)":
        "ninguna (configúralas en arx setup)",
    "base collectors (/proc)":
        "colectores base (/proc)",
    "new SUID binary: {p}":
        "binario SUID nuevo: {p}",
    "whoever runs it does so with its owner's permissions, usually root":
        "quien lo ejecute lo hace con los permisos de su dueño, normalmente root",
    "  no deviations from the baseline ✓":
        "  sin desvíos respecto a la línea base ✓",
    "  ({v} finding(s) already known, unchanged; see: arx status)":
        "  ({v} hallazgo(s) ya conocidos, sin cambios — ver: arx status)",
    "The chat needs an LLM provider. Run:  arx setup":
        "El chat necesita un proveedor LLM. Ejecuta:  arx setup",
    "Arx is not configured. Run:  arx setup":
        "Arx no está configurado. Ejecuta:  arx setup",
    "No sealed baseline. Run:  arx learn  and then  arx learn --seal":
        "No hay línea base sellada. Ejecuta:  arx learn  y luego  arx learn --seal",
    "⚠ Baseline from an earlier version: executables are not watched until you re-learn.\n  (arx learn several times and then arx learn --seal)":
        "⚠ Línea base de una versión anterior: los ejecutables no se vigilan hasta re-aprender.\n  (arx learn varias veces y luego arx learn --seal)",
    "  ⚠ {fn} failed ({name}); the rest continues.":
        "  ⚠ {fn} falló ({name}); el resto sigue.",
    "  ⏱ {n} Tier 1 block(s) expired and were reverted.":
        "  ⏱ {n} bloqueo(s) Tier 1 expiraron y se revirtieron.",
    "\n— sweep {v} —":
        "\n— barrido {v} —",
    "\n  ⚠ {n} new Tier 2 action(s) waiting for your authorization word.":
        "\n  ⚠ {n} acción(es) Tier 2 nuevas esperan tu palabra de autorización.",
    "\n▸ Engine (LLM):\n  ":
        "\n▸ Motor (LLM):\n  ",
    "{k} changed since the baseline was sealed":
        "cambió {k} desde el sellado de la línea base",
    "critical file altered → possible tampering or persistence":
        "fichero crítico alterado → posible manipulación o persistencia",
    "arx> (no response from any provider: {e})":
        "arx> (sin respuesta de ningún proveedor: {e})",
    "  ⚠ the sweep failed ({name}: {e}); still on guard.":
        "  ⚠ el barrido falló ({name}: {e}); sigo en guardia.",
    "  ⚠ the analysis failed ({name}); local defense continues.":
        "  ⚠ el análisis falló ({name}); la defensa local sigue.",
    "error processing the finding ({name})":
        "error al procesar el hallazgo ({name})",
    "you> ":
        "tú> ",
    "✓ {n} active canary(ies):":
        "✓ {n} señuelo(s) activo(s):",
    "▸ {n} canary(ies):":
        "▸ {n} señuelo(s):",
    "   {path}  (planted {v})":
        "   {path}  (plantado {v})",
    "No valid places to plant. Use: arx canaries plant --in <DIR>":
        "No hay ubicaciones válidas donde plantar. Usa: arx canaries plant --in <DIR>",
    "✓ All canaries intact.":
        "✓ Todos los señuelos intactos.",
    "canary RECREATED: {path}":
        "señuelo RECREADO: {path}",
    "the bait file was replaced (different inode)":
        "el fichero-cebo fue reemplazado (inode distinto)",
    "canary GONE: {path}":
        "señuelo DESAPARECIDO: {path}",
    "a deleted honeytoken points to tampering or an intruder's cleanup":
        "un honeytoken borrado indica manipulación o barrido de un intruso",
    "canary MODIFIED: {path}":
        "señuelo MODIFICADO: {path}",
    "nobody legitimate edits a honeytoken → attacker access":
        "nadie legítimo edita un honeytoken → acceso de atacante",
    "canary READ: {path} ({when} UTC)":
        "señuelo LEÍDO: {path} ({when} UTC)",
    "someone opened a honeytoken (possible credential hunting). Note: a backup that reads the whole disk triggers it too.":
        "alguien abrió un honeytoken (posible búsqueda de credenciales). Ojo: un backup que lea el disco entero también lo dispara.",
    "stop SSH accepting passwords, keys only":
        "que SSH no admita contraseñas, solo llaves",
    "root can only log in over SSH with a key":
        "que root solo entre por SSH con llave",
    "unknown proposal {pid}":
        "no conozco la propuesta {pid}",
    "not applied: no admin account has an SSH key, and you would be locked out":
        "no se aplica: ninguna cuenta de administración tiene llave SSH, y te quedarías fuera",
    "not applied: sshd_config does not include {SSHD_DROPIN_DIR}/ and it would have no effect":
        "no se aplica: sshd_config no incluye {SSHD_DROPIN_DIR}/ y no tendría efecto",
    "not applied: sshd does not accept it or keeps another value. It was left as it was":
        "no se aplica: sshd no lo acepta o sigue con otro valor. Se ha dejado como estaba",
    "could not reload sshd: it was left as it was":
        "no se pudo recargar sshd: se ha dejado como estaba",
    "done: {title}. Open sessions stay up. Test it from ANOTHER terminal before closing this one. Undo with:  arx proposals revert {pid}":
        "hecho: {title}. Las sesiones abiertas siguen. Pruébalo desde OTRA terminal antes de cerrar esta. Se deshace con:  arx proposals revert {pid}",
    "proposal {pid} is not applied":
        "la propuesta {pid} no está aplicada",
    ". Note: could not reload sshd, do it by hand":
        ". Ojo: no pude recargar sshd, hazlo a mano",
    "undone: {title}":
        "deshecho: {title}",
    "Arx has nothing to propose right now.":
        "Arx no tiene nada que proponerte ahora mismo.",
    "\n▸ Arx proposes (none of this applies on its own):":
        "\n▸ Arx te propone (nada de esto se aplica solo):",
    "  {id}\n      {title}\n      why: {why}":
        "  {id}\n      {title}\n      por qué: {why}",
    "      ⚠ not possible today: no admin account has an SSH key":
        "      ⚠ hoy no se puede: ninguna cuenta de administración tiene llave SSH",
    "  applied: {a}  ·  undo with:  arx proposals revert {a}":
        "  aplicada: {a}  ·  se deshace con:  arx proposals revert {a}",
    "\nApply one with:  arx proposals apply <id>\n":
        "\nAplica una con:  arx proposals apply <id>\n",
    "Wrong word. Nothing was changed.":
        "Palabra incorrecta. No se ha cambiado nada.",
    "no proposal with id {pid}":
        "no hay ninguna propuesta con id {pid}",
    "you have had {attacks} brute-force attack(s): with this they could no longer work":
        "has recibido {attacks} ataque(s) de fuerza bruta: con esto dejarían de poder funcionar",
    "keeps a weak or stolen password from being enough to get in":
        "evita que una contraseña débil o robada baste para entrar",
    "accept as normal: {v}":
        "aceptar como normal: {v}",
    "seen {seen} times since {v}, with nobody reviewing it":
        "visto {seen} veces desde {v}, sin que nadie lo revisara",
    "CRITICAL":
        "CRÍTICO",
    "\n▸ Listening ports ({n} · {n2} exposed on all interfaces)":
        "\n▸ Puertos en escucha ({n} · {n2} expuestos a todas las interfaces)",
    "\n▸ Users and access":
        "\n▸ Usuarios y accesos",
    "\n▸ Attack surface: {n} findings ({n2} high priority)":
        "\n▸ Superficie de ataque — {n} hallazgos ({n2} de prioridad alta)",
    "\n▸ Proposed defense plan":
        "\n▸ Plan de defensa propuesto",
    "Enable osquery + auditd + Falco/eBPF: system state, syscalls and kernel-level behavior.":
        "Activar osquery + auditd + Falco/eBPF: estado del sistema, syscalls y comportamiento en kernel.",
    "sensors":
        "sensores",
    "Learn what is normal in processes, network, users and schedules (conservative window) with boot integrity.":
        "Aprender lo normal de procesos, red, usuarios y horarios (ventana conservadora) con integridad de arranque.",
    "Plant honeytokens in {v} places (homes + /root) and watch access with inotify.":
        "Plantar honeytokens en {v} ubicaciones (homes + /root) y vigilar acceso con inotify.",
    "Watch for changes in authorized_keys, sudoers, cron and the SUID set; alert on any change.":
        "Vigilar cambios en authorized_keys, sudoers, cron y el conjunto SUID; alertar ante cualquier variación.",
    "integrity":
        "integridad",
    "The engine (LLM) will review this inventory asynchronously and refine the plan with current threat context.":
        "El motor (LLM) revisará este inventario async y afinará el plan con contexto de amenazas actuales.",
    "engine":
        "motor",
    "\n▸ Hardware":
        "\n▸ Hardware",
    "Memory":
        "Memoria",
    "{mem_total_gb} GB ({mem_available_gb} GB free)":
        "{mem_total_gb} GB ({mem_available_gb} GB libres)",
    "Root disk":
        "Disco raíz",
    "{root_disk_gb} GB · {root_used_pct}% used":
        "{root_disk_gb} GB · {root_used_pct}% usado",
    "\n▸ Network":
        "\n▸ Red",
    "  … (+{v} more in the JSON)":
        "  … (+{v} más en el JSON)",
    "\n▸ Active services ({n})":
        "\n▸ Servicios activos ({n})",
    "Humans":
        "Humanos",
    "{n} binaries":
        "{n} binarios",
    "\n▸ Containers ({n} running)":
        "\n▸ Contenedores ({n} en marcha)",
    "  (no deterministic findings; the engine will do the fine review)":
        "  (sin hallazgos deterministas; el motor hará la revisión fina)",
    "▸ Full inventory saved to: {dest}\n":
        "▸ Inventario completo guardado en: {dest}\n",
    "perimeter":
        "perímetro",
    "{proto} {local} listens on all interfaces ({v})":
        "{proto} {local} escucha en todas las interfaces ({v})",
    "unknown process":
        "proceso desconocido",
    "Every exposed port is attack surface; it should be watched and its traffic baselined.":
        "Cada puerto expuesto es superficie de ataque; hay que vigilarlo y basar su tráfico.",
    "Direct root login widens the impact of leaked credentials or brute force.":
        "Login directo de root amplía el impacto de credenciales filtradas o fuerza bruta.",
    "Enables brute force/credential stuffing; keys only is preferable.":
        "Habilita fuerza bruta/credential stuffing; preferible solo claves.",
    "Firewall inactive or not detected (ufw/nftables)":
        "Firewall inactivo o no detectado (ufw/nftables)",
    "Without a firewall, every open port is exposed unfiltered.":
        "Sin firewall, todo puerto abierto queda expuesto sin filtrado.",
    "users":
        "usuarios",
    "{n} SUID binaries (review for excess)":
        "{n} binarios SUID (revisar excesos)",
    "Each SUID is a potential escalation path; set the baseline and watch for changes.":
        "Cada SUID es vía potencial de escalada; conviene fijar la línea base y vigilar cambios.",
    "Root disk at {root_used_pct}%":
        "Disco raíz al {root_used_pct}%",
    "A full disk degrades logs and response; it may also be exfiltration/DoS.":
        "Disco lleno degrada logs y respuesta; también puede ser exfiltración/DoS.",
    "Monitor {n} exposed services; correlate sources and anomalous spikes against the baseline.":
        "Monitorizar {n} servicios expuestos; correlacionar orígenes y picos anómalos contra la base.",
    "Propose a default-deny firewall policy (Tier 2, needs your approval as it may be disruptive).":
        "Proponer política de firewall por defecto-denegar (Tier 2, requiere tu aprobación por ser potencialmente disruptivo).",
    "\n╔═ Arx · initial reconnaissance ":
        "\n╔═ Arx · reconocimiento inicial ",
    "could not":
        "no se pudo",
    "restored":
        "restaurado",
    "done":
        "hecho",
    "undone":
        "deshecho",
    "threat":
        "amenaza",
    "suspicion":
        "sospecha",
    "benign":
        "benigno",
    "unknown":
        "desconocido",
    "clean":
        "limpio",
    "malicious":
        "malicioso",
    "suspicious":
        "sospechoso",
    "valid":
        "válida",
    "insufficient":
        "insuficiente",
    "hostile":
        "hostil",
    "y":
        "s",
    "account":
        "cuenta",
    "id":
        "id",
}
