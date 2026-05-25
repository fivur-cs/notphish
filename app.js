// NotPhish V2 — app.js
// Funciona directamente en browser sin bundler.

// ═══════════════════════════════════════
// SECCIÓN 1: RULES
// ═══════════════════════════════════════

/**
 * NotPhish V2 — rules.js
 * Todas las listas de términos, patrones de reglas y configuración de scoring.
 * Sin lógica de ejecución. Solo datos.
 *
 * Reducción vs V1:
 * - Términos duplicados entre listas eliminados (~40% de reducción en términos)
 * - EDUCATION_CATEGORIES fusionadas con SIGNAL_RULES (era info redundante)
 * - SCAM_PATTERN_LABELS depurado (clave duplicada eliminada)
 * - REGIONAL_PACKS consolidados en las listas base directamente
 * - UNIVERSAL_FRAUD_FAMILIES eliminadas como estructura intermedia
 */

// ─── REGEX BASE ───────────────────────────────────────────────────────────────

const RE = {
  url:         /\b(?:hxxps?:\/\/|https?:\/\/|www\.)[^\s<>()"']+/gi,
  email:       /\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b/gi,
  domain:      /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi,
  placeholder: /\b(?:SUPPORT_EMAIL|NAME_HERE|FIRST_NAME|LAST_NAME|CLIENT_NAME|USER_NAME|EMAIL_HERE|PHONE_HERE|ACCOUNT_ID|INSERT_[A-Z_]+|TEMPLATE_[A-Z_]+)\b|\{\{\s*[\w.-]+\s*\}\}|\[\s*(?:COMPANY|NAME|EMAIL|USER|CLIENT|PHONE|DATE)\s*\]|<<\s*[\w.-]+\s*>>/gi,
  phone:       /\+\d[\d -]{6,}/,
};

// ─── CONFUSABLES (caracteres Unicode que imitan letras latinas) ───────────────

const CONFUSABLES = {
  "ᴄ":"c","ʜ":"h","ɪ":"i","ʟ":"l","ᴇ":"e","ᴘ":"p","ʀ":"r","ꜱ":"s",
  "ѕ":"s","ɑ":"a","ο":"o","о":"o","е":"e","а":"a","і":"i","ӏ":"l",
};

// ─── INFRAESTRUCTURA CONOCIDA ─────────────────────────────────────────────────

const SHORTENERS = new Set([
  "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly","is.gd",
  "cutt.ly","rebrand.ly","shorturl.at","s.id",
]);

// Proveedores de Email Service (ESPs) legítimos.
// Sus subdominios numerados (us8.list-manage.com, em1.sendgrid.net, etc.)
// son infraestructura estándar de email marketing, NO indicadores de phishing.
// La presencia de números en estos subdominios es un artefacto técnico, no evasión.
const KNOWN_ESP_DOMAINS = new Set([
  // Mailchimp / Intuit
  "list-manage.com","mailchi.mp","mc.us","mailchimp.com",
  // SendGrid / Twilio
  "sendgrid.net","sgizmo.com","sendgr.id",
  // Mailjet
  "mailjet.com","mjt.lu",
  // Campaign Monitor
  "cmail1.com","cmail2.com","cmail3.com","cmail20.com","createsend.com",
  // HubSpot
  "hs-email.net","hubspotlinks.com","sidekickopen.com","sidekickapply.com",
  // Constant Contact
  "constantcontact.com","r.conc.re",
  // ActiveCampaign
  "activecampaign.com","lt.acm.ac",
  // Klaviyo
  "klaviyo.com","rkmi.me",
  // Brevo (ex-Sendinblue)
  "brevo.com","sendinblue.com","sibmail.com",
  // Mandrill / Transactional Mailchimp
  "mandrillapp.com",
  // Amazon SES (legítimo, distinto de S3 phishing)
  "amazonses.com",
  // Fidelizador (plataforma ESP chilena)
  "fidelizador.com","fidelizador.cl",
  // Plataformas ESP genéricas conocidas
  "needishmail.com","tmailservice.net","emisor.net","emarsys.net",
  "emailsrvr.com","exacttarget.com","mktoutil.com","mailer.com",
  // Tracking servers comunes en newsletters
  "r.delivery.com","email2.com","e.communications.com",
]);

// Si el dominio base del link es un ESP conocido, los números en el subdominio
// son esperados (us8, em1, etc.) y NO deben activar suspicious_domain.
function isKnownEsp(domain) {
  const reg = regDomain(domain);
  return KNOWN_ESP_DOMAINS.has(reg) || [...KNOWN_ESP_DOMAINS].some(e => reg.endsWith("." + e));
}

const SUSPICIOUS_TLDS = new Set([
  // TLDs usados principalmente para spam/phishing (ccTLDs legítimos excluidos)
  // .us = EE.UU. legítimo (Mailchimp: us8.list-manage.com, us1.campaign-archive.com, etc.)
  // .info = muchos publishers legítimos lo usan
  "buzz","cam","cfd","click","club","country","cyou","download","fit","gq",
  "icu","help","link","live","lol","monster","online","quest","rest",
  "sbs","shop","site","skin","space","store","support","tk","top","vip",
  "website","work","xyz","zip",
]);

const ABUSED_HOSTING = [
  "azurewebsites.net","storage.googleapis.com","firebaseapp.com","web.app",
  "pages.dev","workers.dev","github.io","netlify.app","vercel.app",
  "blob.core.windows.net","s3.amazonaws.com",
];

const SENSITIVE_URL_TOKENS = {
  apikey:        "expone un parámetro apiKey",
  oobcode:       "incluye token de recuperación oobCode",
  resetpassword: "activa un flujo de restablecimiento de contraseña",
  "mode=reset":  "activa modo de reset",
  tenantid:      "incluye tenantId de autenticación",
  "token=":      "incluye un token en la URL",
  "session=":    "incluye una sesión en la URL",
};

const BRAND_DOMAINS = {
  microsoft:   ["microsoft.com","office.com","live.com","outlook.com","microsoftonline.com","microsoft365.com"],
  dhl:         ["dhl.com"],
  paypal:      ["paypal.com"],
  apple:       ["apple.com","icloud.com"],
  google:      ["google.com","gmail.com","accounts.google.com","googlemail.com",
                // Infraestructura de Google usada en HTML de newsletters legítimos
                "googleapis.com","gstatic.com","googleusercontent.com",
                // Servicios y plataformas de Google
                "googlegroups.com","googlevideo.com","googlesyndication.com",
                "google.cl","google.es","google.co"],
  amazon:      ["amazon.com","amazon.cl","amazon.es"],
  netflix:     ["netflix.com"],
  // Couriers chilenos — dominios de envío de email también son legítimos
  chilexpress: ["chilexpress.cl","infochilexpress.cl","notificaciones.chilexpress.cl"],
  starken:     ["starken.cl","notificaciones.starken.cl"],
  correoschile:["correos.cl","correoschile.cl"],
  // Bancos y finanzas — dominios de email marketing son subdominios propios
  bancoestado: ["bancoestado.cl","correobancoestado.cl","mensajeria.bancoestado.cl",
                // Dominios adicionales del grupo BancoEstado
                "emailbancoestado.cl","correo.bancoestado.cl","email.bancoestado.cl",
                // Redirector de campañas de BancoEstado
                "rutero.cl"],
  bancochile:  ["bancochile.cl","portal.bancochile.cl"],
  bci:         ["bci.cl","mail.bci.cl"],
  santander:   ["santander.cl","email.santander.cl"],
  scotiabank:  ["scotiabank.cl","correo.scotiabank.cl"],
  // E-commerce y retail — los retailers tienen dominios de email propios
  falabella:   ["falabella.com","falabella.cl","cl.falabella.com","novedades.falabella.com",
                "cmrfalabella.com","cl.cmrfalabella.com",
                // Entidades del grupo Falabella
                "bancofalabella.cl","cl.bancofalabella.com","bancofalabella.com",
                "segurosfalabella.cl","segurosfalabella.com","cl.segurosfalabella.com",
                // Programa de puntos CMR
                "cmrpuntos.com","cl.cmrpuntos.com",
                // Subdominios de campaña/email del grupo (corp.* son subdominios oficiales)
                "corp.falabella.com","corp.bancofalabella.com"],
  entel:       ["entel.cl","mail.entel.cl"],
  wom:         ["wom.cl"],
  sii:         ["sii.cl"],
  fedex:       ["fedex.com"],
  ups:         ["ups.com"],
  // Plataformas profesionales — sus emails legítimamente mencionan marcas de empleadores
  linkedin:    ["linkedin.com","e.linkedin.com","jobs-listings@linkedin.com",
                "linkedin.com","licdn.com"],
  // Plataformas de streaming/contenido
  youtube:     ["youtube.com","youtubemail.com"],
  // Plataformas de hosting legítimas
  hostgator:   ["hostgator.com","hostgator.cl","hostgator.mx"],
};

const LOOKALIKE_HINTS = {
  micros0ft:"microsoft", paypa1:"paypal", app1e:"apple",
  g00gle:"google", amaz0n:"amazon", chilexpres:"chilexpress",
  chilexpresss:"chilexpress",
};

// Dominios de retailers legítimos que VENDEN marcas de terceros.
// Cuando el remitente pertenece a este conjunto, NO se activa brand_domain_spoof
// por mencionar Apple, Samsung, LG, etc. en el cuerpo del mensaje.
// Un retailer que vende Apple no está suplantando a Apple.
const KNOWN_RETAILER_SENDERS = new Set([
  "pcfactory.cl","medios@pcfactory.cl",
  "cl.falabella.com","falabella.com","novedades@falabella.com",
  "paris.cl","email.paris.cl",
  "buscalibre.com","info@buscalibre.com",
  "linio.com","cl.linio.com",
  "tottus.cl","cl.tottus.com","online@cl.tottus.com",
  "jumbo.cl","unimarc.cl","acuenta.cl","lider.cl",
  "indiegala.com","mailer.humblebundle.com","gog.com","email2.gog.com",
]);

// Marcas de redes sociales que aparecen en footers legítimos de newsletters.
// Cuando varias de estas aparecen juntas ("Síguenos en LinkedIn Instagram Facebook"),
// es un footer estándar — NO es brand_content_spoof.
const SOCIAL_FOOTER_BRANDS = new Set([
  "linkedin","instagram","facebook","twitter","youtube","tiktok","reddit",
  "pinterest","snapchat","threads","whatsapp","telegram","discord","twitch",
]);

// Contexto de footer social: frases que acompañan a iconos de redes en newsletters.
const SOCIAL_FOOTER_CONTEXT = [
  "síguenos","siguenos","follow us","encuéntranos","encuentranos",
  "redes sociales","social media","stay connected","connect with us",
  "follow","twitter","instagram","facebook","linkedin","youtube",
  "unsubscribe","cancelar suscripción","darse de baja","optout",
];

// Dominios de plataformas que envían alertas de seguridad legítimas.
// Sus correos de "nuevo inicio de sesión" o "alerta de seguridad" no son phishing.
const SECURITY_NOTIFICATION_SENDERS = new Set([
  "accounts.google.com","no-reply@accounts.google.com",
  "security@google.com","googlemail.com",
  "microsoftonline.com","microsoft.com","account-security-noreply@accountprotection.microsoft.com",
  "id.apple.com","apple.com",
  "security@linkedin.com","linkedin.com","e.linkedin.com",
  "github.com","noreply@github.com",
  "security@amazon.com","amazon.com",
  // Plataformas de gestión remota y gaming con alertas de seguridad legítimas
  "logmein.com","logme.in","lastpass.com",
  "steampowered.com","no-reply@steampowered.com",
  "epicgames.com","riotgames.com","mail.accounts.riotgames.com",
  "battle.net","blizzard.com","ncsoft.com",
  "discord.com","discordapp.com",
  "twitch.tv","notion.so","slack.com",
]);

// Patrones textuales que indican que el correo es una alerta de seguridad protectora,
// NO una solicitud de credenciales fraudulenta.
const SECURITY_NOTICE_PHRASES = [
  "si no fuiste tú","si no lo solicitaste","si no realizaste esta acción",
  "if this wasn't you","if you didn't do this","if you didn't make this change",
  "if you did not request","didn't request this","no reconoces esta actividad",
  "no reconoces este acceso","si no reconoces","you can ignore this message",
  "you don't need to take any action","no action is required",
  "ignora este mensaje si fuiste tú","puedes ignorar este correo",
  "this was you? no action needed","si eres tú no tienes que hacer nada",
];

const SUSPICIOUS_SUBDOMAIN_WORDS = [
  "verify","login","signin","secure","account","update","support",
  "billing","payment","delivery","tracking","reset","auth",
];

const SUSPICIOUS_DOMAIN_WORDS = [
  "account","check","userportal","portal","auth","reset","secure",
  "security","verify","login","banking","credential","credentials",
];

const ENTITY_STOPWORDS = new Set([
  "hola","asunto","gracias","noreply","no","reply","notifications",
  "notification","notificaciones","soporte","support","team","equipo",
  "area","administracion","recursos","humanos","finanzas","logo",
  "estimado","usuario","cliente","portal","secure","security","login",
  "account","delivery","tracking",
]);

// ─── LISTAS DE TÉRMINOS ───────────────────────────────────────────────────────
// Cada lista cubre su categoría sin duplicar entre listas.
// Los términos duplicados de la V1 se eliminaron o consolidaron aquí.

const TERMS = {
  urgency: [
    // Urgencia genuinamente sospechosa (acción de cuenta / bloqueo / seguridad)
    "suspendido","última oportunidad","ultima oportunidad",
    "acción requerida","accion requerida","bloqueo","vencido","detenido",
    "today","expires","action required","confirmación requerida","confirmacion requerida",
    "antes de continuar","keep access active","acceso temporalmente limitado",
    "mantener acceso normal","evitar retrasos","retrasos innecesarios",
    "acción inmediata requerida","accion inmediata requerida","de inmediato",
    "cierre semanal","mantener la continuidad del servicio","disponibilidad del servicio",
    "durante la jornada","apenas puedas","este pendiente","esté pendiente",
    // Términos problemáticos que en contexto comercial son normales:
    // "urgente","hoy","ahora" — se quitaron porque disparan demasiado en marketing
    // Se mantienen en detectBec() donde el contexto es más preciso
  ],

  // Urgencia COMERCIAL: normal en marketing, no debe puntuar como fraude.
  // Se usa para detectar y no activar el detector de urgencia cuando el contexto es comercial.
  commercial_urgency: [
    "últimas unidades","ultimas unidades","solo hoy","last chance","oferta válida hasta",
    "oferta valida hasta","aprovecha ahora","no te lo pierdas","tiempo limitado",
    "limited time","stock limitado","agotarse","liquidación","liquidacion",
    "cyber","cyberday","black friday","oferta del día","oferta del dia",
    "descuento de hoy","termina hoy","vence hoy","solo por hoy","válido hasta",
    "valido hasta","oferta especial","precio especial",
  ],

  authority: [
    "banco","soporte técnico","soporte tecnico","policía","policia","impuestos",
    "dhl","microsoft","paypal","apple","google","amazon","netflix","chilexpress",
    "correos de chile","aduana","courier","delivery","shipping","support","payment",
    "firebase","administración","administracion","área logística","area logistica",
    // Regional
    "sii","bancoestado","falabella","entel","movistar","wom",
    "hacienda","agencia tributaria","correos","caixabank","santander",
  ],

  ambiguity: [
    "estimado cliente","querido cliente","paquete pendiente","problema con su cuenta",
    "actividad inusual","su cuenta","cambio reciente en su perfil","perfil",
    "portal seguro","acceso será limitado","acceso sera limitado","información pendiente",
    "informacion pendiente","verificación pendiente","verificacion pendiente",
    "nueva notificación","nueva notificacion","notificación de seguimiento",
    "notificacion de seguimiento","código de seguimiento","codigo de seguimiento",
    "hello","your account","your pending","pending:","portal indicado",
    "solicitud fue registrada","dear user","continuidad de acceso",
  ],

  risky_action: [
    "iniciar sesión","iniciar sesion","verificar cuenta","descargar archivo",
    "pagar ahora","actualizar datos","confirmar información","confirmar informacion",
    "restablecer contraseña","cambiar contraseña","abrir adjunto","validar identidad",
    "follow this link","reset your password","create password","verify account",
    "sign in","login","log in","reset password","password expires","credentials",
    "credential","credenciales","valide sus credenciales","validar credenciales",
    "updating credentials","confirme los datos","confirm data","ingrese al sistema",
    "actualice la información","actualice la informacion","acceso será limitado",
    "información de acceso","informacion de acceso","continuidad de acceso",
    "datos del perfil","información del perfil","confirmación breve","confirmacion breve",
    "regularización","regularizacion","revisión pendiente","revision pendiente",
    "validar información","validar informacion","validación menor","validacion menor",
    "profile has been locked","profile has been restricted","account has been restricted",
    "account has been locked","restore access","verification code","2fa code",
    "two factor","passcode","username","secure link","enter your verification code",
    "programar entrega ahora","gestionar entrega","confirmar","portal indicado",
    "pago aduanero","cargo aduanero","tarifa de entrega","confirme sus detalles",
    "continuar","darse de baja aquí","darse de baja aqui","completa la validación",
    "completa la validacion","indicar nueva disponibilidad","reprogramar entrega",
  ],

  money: [
    "$","facturación","facturacion","saldo pendiente","payout","payment","claim",
    "free cash","freecash","reward","prize","gift card","earn money",
    // Patrones de pago/transferencia en español
    "transferencia","te transfiero","te transferiré","envíame el dinero",
    "enviame el dinero","te devuelvo","te lo devuelvo","hazte la transferencia",
    "hacer la transferencia","hazme la transferencia","me transfieres",
    "quiero pagar","necesito pagar","pagar la","hacer un pago",
  ],

  delivery: [
    "paquete suspendido","paquete no reclamado","no reclamado",
    "entrega del paquete suspendido","centro de distribución","centro de distribucion",
    "gestionar entrega","despacho","listo para despacho","último intento de entrega",
    "ultimo intento de entrega","entrega programada","devolución automática",
    "devolucion automatica","franja horaria","nueva franja horaria",
    "no fue posible completar la entrega","nueva disponibilidad","indicar horario",
    "reprogramar entrega","nueva fecha de entrega","cargo aduanero pendiente",
    "tarifa de entrega","código de seguimiento","codigo de seguimiento",
    "programar entrega","starken",
    // Regional
    "encomienda","aduanero","retiro","paquete retenido","aduana",
  ],

  soft_manipulation: [
    "documento interno pendiente","solicitamos revisar el documento compartido",
    "dejar constancia de lectura","necesitamos cerrar esto hoy",
    "revísalo apenas puedas","revisalo apenas puedas","confirma cuando lo veas",
    "pendiente de validación","pendiente de validacion","actualización requerida",
    "actualizacion requerida","queda un paso final","necesitamos tu respuesta hoy",
    "se solicita respuesta inmediata","agradecemos gestionar esto hoy",
    "solo falta una confirmación final","solo falta una confirmacion final",
    "cerrar tu solicitud","revisarlo hoy","actualización de política interna",
    "actualizacion de politica interna","actualización interna importante",
    "confirmación de lectura","confirmacion de lectura",
  ],

  institutional_authority: [
    "recursos humanos","rrhh","administración","administracion","dirección","direccion",
    "gerencia","finanzas","soporte","it team","seguridad","jurídico","juridico",
    "compliance","auditoría","auditoria","rectoría","rectoria","tesorería","tesoreria",
  ],

  dangerous_ambiguity: [
    "asunto pendiente","revisión necesaria","revision necesaria","problema detectado",
    "incidencia reciente","actualización de perfil","actualizacion de perfil",
    "revisar información","revisar informacion","acceso limitado","proceso incompleto",
    "validación pendiente","validacion pendiente","documento compartido",
    "acción pendiente","accion pendiente","información asociada","informacion asociada",
    "validación menor","validacion menor","regularización","regularizacion",
    "revisar antecedentes","ajuste pendiente",
    // Nuevos: lenguaje GDPR/legal como pretexto
    "consentimiento de tratamiento","renovar consentimiento","consentimiento próximo a vencer",
    "consentimiento vence","datos personales vencen","tratamiento de datos",
    "normativa vigente","en cumplimiento","imperativo legal","por imperativo",
    "antes de que su cuenta","antes de que tu cuenta",
  ],

  emotional_engineering: [
    "evitar bloqueo","no perder acceso","mantenga beneficios","proteger su cuenta",
    "evitar cargos","evitar devolución","evitar devolucion","se perderá la oportunidad",
    "se perdera la oportunidad","mantenga continuidad operativa",
    "evitaremos retrasos innecesarios","conservar acceso","conservar uso normal",
    "mantener disponibilidad normal",
    // BEC indirecto emocional
    "discretamente","de forma discreta","de manera discreta","en privado",
    "guardalo entre nosotros","no lo comentes todavía","no lo comentes todavia",
    "entre nosotros","solo tú","solo tu","sin que nadie más sepa",
    "sin que nadie mas sepa",
  ],

  bec: [
    "necesito transferencia urgente","compra gift cards","comprar gift cards",
    "necesito este pago hoy","envíame tu número","enviame tu numero",
    "maneja esto con discreción","maneja esto con discrecion",
    "no llames ahora","no llames por ahora","no puedo hablar",
    "no puedo atender llamadas","ahora no puedo hablar","estoy entrando a reunión",
    "estoy entrando a reunion","estoy complicado ahora","estoy ocupado",
    "estoy entre reuniones","necesito que gestiones esto","necesito apoyo urgente",
    "necesito que avances","avances con esto","avanza con esto",
    "encargate de esto","encárgate de esto","gestiones esto de inmediato",
    "hazlo apenas puedas","confirmes apenas esté hecho","confirmes apenas este hecho",
    "avísame cuando quede listo","avisame cuando quede listo","apenas quede resuelto",
    "confirmes cuando esté listo","confirmes cuando este listo","después te explico",
    "despues te explico","luego vemos detalles","estoy en reunión","estoy en reunion",
    "hazlo de inmediato","gestiones un pago hoy","confírmame apenas lo veas",
    "confirmame apenas lo veas",
    // Gift card BEC
    "tarjeta de regalo","tarjetas de regalo","gift card","gift cards",
    "compra tarjetas","compra las tarjetas","carga las tarjetas",
    "manda los codigos","manda los códigos","envíame los códigos",
    "enviame los codigos","guarda los codigos","guarda los códigos",
    // BEC indirecto (sin palabras obvias de transferencia)
    "de manera discreta","de forma discreta","no lo comentes","no lo menciones",
    "no lo hables con","guardalo entre nosotros","es confidencial",
    "no uses los canales habituales","no puedo comunicarme",
    "necesito un favor discreto","hacerme un favor urgente",
    "no me llames ahora","apenas puedas escríbeme","apenas puedas escribeme",
    "una operación urgente","gestionar algo de manera",
  ],

  tech_support: [
    "it department detected","malware infection","workstation","run the antivirus scan",
    "antivirus scan","install the security patch","security patch","fix the issue",
    "spyware","technical support","system administrator","comportamiento no habitual",
    "estación de trabajo","estacion de trabajo","revisión preventiva","revision preventiva",
    "conviene revisar","configuración aplicada","configuracion aplicada",
    "tu dispositivo presenta amenazas","contacta soporte ahora",
    "microsoft security warning","suspicious activity detected",
    "señales de infección","señales de infeccion","sigue las instrucciones para corregirlo",
  ],

  threat_pressure: [
    "final warning","failure to respond","immediate action is required",
    "avoid fine","avoid penalty","avoid legal action","legal action",
    "case will be referred","referred to the judge","if unresolved",
    "lawsuit","prosecution","summons","will block your account",
    "will hold your account","will restrict your account",
  ],

  reward_scam: [
    "congratulations","winner of a prize","winner of a refund","selected recipient",
    "collect your gift","collect your payment","redeem your payment",
    "provide your credit card","provide your account number","available today only",
    "jackpot","contest","won a guaranteed","claim yr prize","caller prize",
    "bonus caller prize",
    // Español
    "saliste sorteado","fue seleccionado","fue seleccionada","ganador seleccionado",
    "ganadora seleccionada","reclama tu regalo","reclama tu premio",
    "tu premio te espera","retira tu premio","sorteo de falabella",
    "sorteo de ripley","sorteo oficial","premio en efectivo",
    "envía tu rut","envía tu dirección","proporciona tus datos",
    "giro de dinero","transferir el premio",
  ],

  romance_loan: [
    "we talked about meeting","unexpected situation came up","business trip",
    "wallet was stolen","temporary loan","emergency loan","transfer back next week",
    "stranded traveler","replacement cards","extend stay","hotel is asking",
    "payment verification failed","assist with an emergency loan",
    "confío en ti","confio en ti",
    // Español
    "robaron la billetera","robaron el pasaporte","estoy varado","estoy varada",
    "no tengo dinero","pagar el hotel","pagar la cirugía","pagar la cirugia",
    // Removidos por FP: "te devuelvo","cuando llegue" son comunes en e-commerce/courier
    // "urgencia familiar" puede ser real pero sin contexto de dinero no es suficiente
    "urgencia familiar","accidente","me ayudas con",
    "me robaron","necesito que me transfieras","hacerme una transferencia",
    "préstamo rápido","prestamo rapido","te pago mañana","te pago manana",
  ],

  premium_sms: [
    "txtStop","STOP2END","rcd","custcare:","po box","pobox",
    "call 087","0871","box95",
  ],

  generic_link: [
    "please click here","click here to view","view the update",
    "link and attachment","attachment are included","provided link",
    "do not reply to this auto-generated message",
  ],

  commercial_scam: [
    "viagra","cialis","pharmacy","online pharmacy","replica","replica rolex",
    "rolex","watches","fake watches","fake luxury","cheap meds","meds online",
    "miracle pills","enlargement","penis enlargement","adult gallery",
    "adult bait","ecard","e-card","porno","porn",
    // Crypto scam
    "retorno garantizado","retornos garantizados","sin riesgo","30% mensual",
    "15% mensual","garantizado mensual","inversion segura","inversión segura",
    "seed phrase","frase semilla","connect wallet","conectar wallet",
    "airdrop","staking rewards","claim tokens","nft exclusive",
    // Money mule
    "procesar pagos","representante regional","reenviar fondos",
    "transferencias de clientes","comision del","comisión del",
    "mula de dinero",
    // Premium SMS / sorteos
    "txt win","txtwin","custcare","caller prize","box 95","stop2end",
    "saliste sorteado","fue seleccionado para","premio mayor","gana dinero facil",
    "gana dinero fácil","retira tu premio","reclamar premio",
  ],

  // Señales POSITIVAS — bajan el score
  legit_newsletter: [
    "unsubscribe","manage preferences","newsletter","view in browser",
    "view this email in your browser","published by","manage subscriptions",
    "mailing list","digest","jobs board","member update","privacy policy",
    "subscription preferences","email preferences","you are receiving this email",
    "this message was sent to",
  ],

  legit_sms: [
    "successfully registered a new beneficiary","if you did not make this request",
    "transaction alert","no lo comparta","si usted no solicito este codigo",
    "do not share this code","if you did not request this code",
    "one time password","otp for your transaction","verification code for your account",
    "paquete llega mañana","paquete fue entregado","pedido fue entregado",
    "no debes realizar ninguna acción","no debes realizar ninguna accion",
    "no es necesario actualizar datos","no pediremos claves ni códigos",
    "no pediremos claves ni codigos",
  ],

  legit_chat: [
    "llegué bien a la casa","llegue bien a la casa","luego te llamo","con calma",
    "si tienes dudas","correo corporativo","no necesito nada","solo para que lo guardes",
    "no hace falta que respondas","ignore este mensaje","ignora este mensaje",
    "pago contra entrega","te pago cuando lo retire","efectivo cuando retire",
  ],

  legit_job: [
    "equal opportunity employer","benefits package","hybrid schedule",
    "health insurance","paid time off",
  ],

  legit_marketplace: [
    "compra presencial","entrega presencial","pago contra entrega",
    "revisar el producto antes de pagar","boleta","comprobante","recibo",
  ],

  legit_social: [
    "te copiaron el perfil","reportar cuenta falsa","cambié mi contraseña",
    "cambie mi contraseña","activar verificación en dos pasos",
    "activar verificacion en dos pasos",
  ],

  // Agrupaciones compuestas (fusionan V1 UNIVERSAL_FRAUD_FAMILIES + REGIONAL_PACKS)
  reward_loyalty: [
    "puntos","saldo de puntos","puntos por vencer","canje","recompensa","redeem",
    "redeem points","loyalty","reward points","rut","bono","subsidio",
    "saldo promocional","premio","points balance","redeem now","loyalty balance",
  ],

  government_tax: [
    "multa","impuesto","deuda","citación","citacion","hacienda","agencia tributaria",
    "sii","recargo","dni","tax debt","fine notice","court summons","boleta",
  ],

  telco: [
    "línea suspendida","linea suspendida","recarga de datos","saldo de datos","portabilidad",
    "service line","mobile line","data pack","bizum","movistar","vodafone","orange",
    "internet hogar","service suspended","mobile benefit","data plan",
    "saldo promocional",
  ],

  otp_mfa: [
    "codigo","código","verificacion","verificación","otp","mfa",
    "autenticación","autenticacion","restablecer acceso","one-time",
    "passcode","verification code","2fa code","two factor",
  ],

  // Contexto de "código" que es COMERCIAL/PROMOCIONAL, no OTP de seguridad.
  // Si estos términos están presentes, el detector OTP reduce su puntuación.
  promo_code_context: [
    "codigo de descuento","código de descuento","código promocional","codigo promocional",
    "cupon","cupón","coupon","promo code","discount code","código de oferta",
    "codigo de oferta","ver código","ver codigo","usar código","usar codigo",
    "canjear código","canjear codigo","ingresa el código en","ingresa el codigo en",
    "codigo de reserva","numero de reserva","codigo de vuelo","booking code",
    "codigo de confirmacion","código de confirmación","localizador","numero de localizador",
    "codigo de seguimiento","código de seguimiento","número de seguimiento",
    "order number","número de pedido","numero de pedido","código de producto",
    // Documentos oficiales y certificados — "código" aparece en contexto documental
    "certificado","documento adjunto","adjuntamos el documento","documento solicitado",
    // Cupones cortos tipo FLASH, FIESTA, EXTRA (normalizados sin espacios)
    "codigo flash","codigo fiesta","codigo extra","usando codigo","usando el codigo",
    "código flash","código fiesta","obtén un","descuento adicional",
    // Ingresa código en TIENDA / app (no en login de cuenta)
    "ingresa tu codigo en","ingresa el codigo en nuestra","ingresa en nuestra tienda",
    "ingresar en tienda","en caja","en el local","ingresa en caja",
    // Regalo / sorpresa comercial (Tottus, etc.)
    "regalo perfecto","descubre la sorpresa","codigo de regalo","codigo regalo",
    "tarjeta regalo","gift card para","es para ti","te enviamos el codigo",
    // Gamificación y contexto académico — plataformas educativas, apps con puntos/estrellas
    // "código para obtener estrellas", "código de beneficio", "activar herramienta"
    // son incentivos de app o recompensas académicas, NO verificación de cuenta/OTP
    "para obtener","estrellas gratuitamente","dias gratuitamente","puntos gratuitos",
    "codigo para obtener","código para obtener","codigo de beneficio","código de beneficio",
    "activar el beneficio","activar beneficio","herramienta de","codigo de recompensa",
    "para canjear","para reclamar","acceso gratuito","dias gratis","puntos gratis",
  ],

  officiality: [
    "sitio oficial","página oficial","pagina oficial","web oficial",
    "portal oficial","official site","official portal","official website",
    "official web portal",
  ],
};

// ─── SIGNAL RULES (fusiona V1 EDUCATION_CATEGORIES + modo-specific rules) ────
// Cada regla define: id, label, terms[], score, isThreat, isManipulation,
// explanation (para el usuario), advice (consejo educativo).

const SIGNAL_RULES = [
  {
    id:            "credential",
    label:         "Credenciales",
    terms:         TERMS.risky_action.filter(t =>
                     /login|sign|password|contraseña|credencial|sesion|sesión|cuenta|identidad|access|acceso/i.test(t)
                   ),
    score:         18,
    isThreat:      true,
    explanation:   "Pide acceso, contraseña o datos de cuenta. Señal fuerte si no esperabas el mensaje.",
    advice:        "Entra al sitio oficial directamente; nunca desde el enlace del mensaje.",
  },
  {
    id:            "urgency",
    label:         "Urgencia",
    terms:         TERMS.urgency,
    score:         12,
    isManipulation:true,
    isWeak:        true,   // ← WEAK: urgencia comercial es normal en marketing
    explanation:   "Te apura para que decidas rápido y verifiques menos.",
    advice:        "Respira. Los mensajes urgentes de verdad no pierden nada si los verificas antes.",
  },
  {
    id:            "authority",
    label:         "Autoridad o marca",
    terms:         [...TERMS.authority, ...TERMS.institutional_authority],
    score:         10,
    isManipulation:true,
    isWeak:        true,   // ← WEAK: mención de marca ≠ amenaza, no mostrar en UI
    explanation:   "Usa una marca, cargo o área para parecer confiable y generar obediencia.",
    advice:        "Verifica que el remitente y el dominio correspondan a la entidad real.",
  },
  {
    id:            "ambiguity",
    label:         "Ambigüedad",
    terms:         [...TERMS.ambiguity, ...TERMS.dangerous_ambiguity],
    score:         8,
    isManipulation:true,
    isWeak:        true,   // ← WEAK: señal de análisis interno, no de amenaza visible
    explanation:   "Lenguaje genérico o poco verificable, como si pudiera enviarse a muchas personas.",
    advice:        "Pregunta qué cuenta, documento o proceso específico se menciona.",
  },
  {
    id:            "action",
    label:         "Acción requerida",
    terms:         [...TERMS.risky_action, ...TERMS.generic_link],
    score:         16,
    isThreat:      true,
    isWeak:        true,   // ← WEAK solo: necesita combinarse con link raro o urgencia real
    explanation:   "Quiere que hagas algo concreto. Si el contexto no es claro, puede ser peligroso.",
    advice:        "Antes de actuar, confirma por otro canal.",
  },
  {
    id:            "delivery",
    label:         "Entrega o courier",
    terms:         TERMS.delivery,
    score:         20,
    isManipulation:true,
    isWeak:        true,   // ← WEAK solo: entrega legítima en e-commerce es normal
    explanation:   "Los mensajes de paquetes se usan para empujar pagos, datos o clics rápidos.",
    advice:        "Revisa el seguimiento desde la web oficial de la empresa.",
  },
  {
    id:            "money",
    label:         "Pago o premio",
    terms:         [...TERMS.money, ...TERMS.reward_scam, ...TERMS.reward_loyalty],
    score:         18,
    isThreat:      true,
    isWeak:        true,   // ← WEAK: pago/premio en newsletter/transaccional es normal
    explanation:   "Hablar de pagos, premios o beneficios puede ser un gancho para obtener datos.",
    advice:        "Desconfía si te piden pagar, reclamar o regularizar desde un enlace.",
  },
  {
    id:            "bec",
    label:         "Fraude corporativo",
    terms:         TERMS.bec,
    score:         28,
    isThreat:      true,
    isManipulation:true,
    explanation:   "Instrucción con urgencia y poca explicación. Patrón típico de fraude corporativo.",
    advice:        "Confirma con la persona por un canal conocido antes de actuar.",
  },
  {
    id:            "tech_support",
    label:         "Soporte falso",
    terms:         TERMS.tech_support,
    score:         18,
    isThreat:      true,
    explanation:   "Se presenta como soporte técnico para que hagas algo riesgoso.",
    advice:        "El soporte real nunca pide instalar nada desde un correo.",
  },
  {
    id:            "threat",
    label:         "Amenaza o bloqueo",
    terms:         TERMS.threat_pressure,
    score:         18,
    isThreat:      true,
    explanation:   "Mete miedo con bloqueo, multa o pérdida de acceso para empujar una acción.",
    advice:        "Verifica fuera del mensaje antes de entregar datos o pagar.",
  },
  {
    id:            "emotional",
    label:         "Manipulación",
    terms:         [...TERMS.emotional_engineering, ...TERMS.soft_manipulation],
    score:         12,
    isManipulation:true,
    isWeak:        true,   // ← WEAK: emoción sola sin evidencia técnica = interno
    explanation:   "Usa presión emocional o lenguaje suave para que actúes sin suficiente información.",
    advice:        "Pide contexto y confirma por otro canal.",
  },
  {
    id:            "government",
    label:         "Entidad pública",
    terms:         TERMS.government_tax,
    score:         18,
    isThreat:      true,
    isWeak:        true,   // ← WEAK: mención informativa de entidad pública ≠ fraude
    explanation:   "Usa lenguaje de impuestos, deuda o multa para meter presión.",
    advice:        "Comprueba el trámite desde la web real del organismo.",
  },
  {
    id:            "otp",
    label:         "OTP / Código",
    terms:         TERMS.otp_mfa,
    score:         18,
    isThreat:      true,
    isWeak:        true,   // ← WEAK: "código" es muy ambiguo sin contexto de compartir
    explanation:   "Si piden OTP o código de verificación, podrías estar entregando acceso a tu cuenta.",
    advice:        "Nunca compartas códigos de acceso desde mensajes dudosos.",
    // Fix D: excluir contextos donde "código" es comercial/promo/documental, no OTP
    exclude:       [
      // Reservas, vuelos, pedidos
      "codigo de reserva","numero de reserva","codigo de vuelo","booking code",
      "codigo de confirmacion de vuelo","numero de pedido","numero de orden",
      // Cupones y descuentos (formas cortas y largas)
      "codigo de descuento","código de descuento","codigo promocional","código promocional",
      "cupon","cupón","coupon","promo code","discount code","codigo de oferta",
      "canjear codigo","usar codigo","ver codigo","codigo flash","codigo fiesta",
      "codigo extra","codigo off","codigo gratis","obtén un","obtén el codigo",
      // Seguimiento / logística
      "codigo de seguimiento","código de seguimiento","numero de seguimiento",
      // Documentos y certificados (SII, Registro Civil, municipios)
      "certificado","adjuntamos el","documento solicitado","código de verificacion de compra",
      "codigo de producto","ver tu código","ver tu codigo",
      "codigo flash","codigo fiesta","codigo extra","usando codigo","usando el codigo",
      "regalo perfecto","descubre la sorpresa","codigo regalo","codigo de regalo",
      "ingresa tu codigo en","ingresa en nuestra tienda","en caja","en el local",
      // Gamificación / académico
      "para obtener","estrellas gratuitamente","dias gratuitamente","puntos gratuitos",
      "codigo para obtener","codigo de beneficio","activar el beneficio","activar beneficio",
      "herramienta de","para canjear","para reclamar","acceso gratuito","dias gratis",
    ],
  },
  {
    id:            "telco",
    label:         "Telco / Línea",
    terms:         TERMS.telco,
    score:         16,
    isManipulation:true,
    isWeak:        true,   // ← WEAK: número de teléfono en correo es muy común
    explanation:   "Usa saldo, plan o portabilidad para empujarte a actuar.",
    advice:        "Revisa tu línea desde la app oficial de la compañía.",
  },
  {
    id:            "romance",
    label:         "Romance / Préstamo",
    terms:         TERMS.romance_loan,
    score:         24,
    isThreat:      true,
    isManipulation:true,
    explanation:   "Usa cercanía emocional o emergencia para pedir dinero.",
    advice:        "Habla con esa persona por otro canal antes de cualquier transferencia.",
  },
  {
    id:            "commercial",
    label:         "Spam / Scam clásico",
    terms:         [...TERMS.commercial_scam, ...TERMS.premium_sms],
    score:         22,
    isThreat:      true,
    isWeak:        true,   // ← WEAK: lenguaje comercial agresivo no es scam por sí solo
    explanation:   "Lenguaje típico de spam comercial o estafas clásicas.",
    advice:        "No compres ni entregues datos desde este tipo de mensaje.",
  },
  {
    id:            "officiality",
    label:         "Señuelo de oficialidad",
    terms:         TERMS.officiality,
    score:         12,
    isManipulation:true,
    isWeak:        true,   // ← WEAK: decir "oficial" es muy frecuente en legítimos también
    explanation:   "Decir 'oficial' no vuelve real un correo. Recurso para parecer legítimo.",
    advice:        "Valida el dominio completo, no solo la frase 'portal oficial'.",
  },
  // Señales de CONFIANZA (score negativo)
  {
    id:            "trust_newsletter",
    label:         "Newsletter legítimo",
    terms:         TERMS.legit_newsletter,
    score:         -10,
    isTrust:       true,
    explanation:   "Señal típica de newsletter o marketing legítimo.",
    advice:        "Úsalo como punto a favor, no como prueba definitiva.",
    modes:         ["email","chat"],
  },
  {
    id:            "trust_sms",
    label:         "OTP transaccional",
    terms:         TERMS.legit_sms,
    score:         -12,
    isTrust:       true,
    explanation:   "Frase típica de código legítimo.",
    advice:        "Combínalo con revisión del remitente.",
    modes:         ["sms"],
  },
  {
    id:            "trust_chat",
    label:         "Contexto conversacional benigno",
    terms:         TERMS.legit_chat,
    score:         -6,
    isTrust:       true,
    explanation:   "Más propio de conversación legítima.",
    advice:        "Verifica igual el contexto completo.",
    modes:         ["chat"],
  },
  {
    id:            "trust_job",
    label:         "Vacante legítima",
    terms:         TERMS.legit_job,
    score:         -8,
    isTrust:       true,
    explanation:   "Indicador más típico de empleo real.",
    advice:        "Busca la empresa en fuentes independientes.",
    modes:         ["fake_job"],
  },
  {
    id:            "trust_marketplace",
    label:         "Compraventa más segura",
    terms:         TERMS.legit_marketplace,
    score:         -10,
    isTrust:       true,
    explanation:   "Práctica más verificable para compraventa.",
    advice:        "Prefiere siempre el pago contra entrega.",
    modes:         ["marketplace"],
  },
  {
    id:            "trust_social",
    label:         "Cuidado de cuenta",
    terms:         TERMS.legit_social,
    score:         -10,
    isTrust:       true,
    explanation:   "Habla de proteger o verificar una cuenta sin pedir códigos.",
    advice:        "Verifica que no haya links extraños en el mensaje.",
    modes:         ["social"],
  },
];

// ─── COMBINACIONES (combo detection) ─────────────────────────────────────────
// Cada combo requiere que los ids listados en needs estén presentes en alerts.

const COMBOS = [
  { id:"credential_urgency",      needs:["credential","urgency"],               score:26, label:"Credenciales + urgencia",              family:"bank_credential_scam",       isThreat:true, isManipulation:true,
    detail:"El mensaje mezcla solicitud de acceso/datos con presión temporal, patrón clásico de phishing." },
  { id:"delivery_action",         needs:["delivery","action"],                  score:24, label:"Entrega + acción requerida",           family:"delivery_courier_scam",      isThreat:true, isManipulation:true,
    detail:"La entrega aparece retenida o suspendida y se pide confirmar/reprogramar." },
  { id:"authority_credential",    needs:["authority","credential"],             score:24, label:"Autoridad + credenciales",             family:"bank_credential_scam",       isThreat:true, isManipulation:true,
    detail:"Combina marca o autoridad con solicitud de validación de acceso." },
  { id:"bec_urgency",             needs:["bec","urgency"],                      score:40, label:"BEC + urgencia",                       family:"boss_impersonation",         isThreat:true, isManipulation:true,
    detail:"Señales de fraude corporativo con presión temporal. Patrón de alta peligrosidad." },
  { id:"bec_authority",           needs:["bec","authority"],                   score:35, label:"BEC + autoridad",                      family:"boss_impersonation",         isThreat:true, isManipulation:true,
    detail:"Delega una acción sensible usando autoridad jerárquica con poca explicación." },
  { id:"tech_action",             needs:["tech_support","action"],             score:24, label:"Soporte técnico + acción",             family:"tech_support_scam",          isThreat:true,
    detail:"Usa soporte técnico o malware para empujar instalación, parche o enlace." },
  { id:"threat_action",           needs:["threat","action"],                   score:24, label:"Amenaza + acción",                     family:"threat_credential_combo",    isThreat:true, isManipulation:true,
    detail:"Mezcla amenaza de bloqueo, multa o acción legal con una acción de cuenta." },
  { id:"money_action",            needs:["money","action"],                    score:24, label:"Premio/pago + acción",                  family:"reward_scam",                isThreat:true,
    detail:"Ofrece premio, reembolso o pago y pide una acción o dato financiero." },
  { id:"romance_money",           needs:["romance","money"],                   score:22, label:"Historia personal + dinero",           family:"romance_loan_scam",          isThreat:true, isManipulation:true,
    detail:"Cercanía emocional o emergencia para pedir dinero o transferencia." },
  { id:"government_money",        needs:["government","money"],                score:24, label:"Entidad pública + pago",               family:"government_tax_fine_scam",   isThreat:true,
    detail:"Usa oficialidad pública y tema de deuda o multa para empujar pago." },
  { id:"ambiguity_credential",    needs:["ambiguity","credential"],            score:20, label:"Ambigüedad + credenciales",            family:"soft_account_validation",    isThreat:true, isManipulation:true,
    detail:"Lenguaje vago de cuenta o validación para obtener datos o acceso." },
  { id:"emotional_action",        needs:["emotional","action"],                score:16, label:"Presión emocional + acción",           family:"emotional_manipulation",     isManipulation:true,
    detail:"Usa consecuencias negativas o beneficios para empujar una acción." },
  { id:"otp_urgency",             needs:["otp","urgency"],                     score:26, label:"OTP + urgencia",                       family:"otp_mfa_scam",               isThreat:true, isManipulation:true,
    detail:"Pide un código de verificación con presión temporal. Señal fuerte de robo de cuenta." },
  { id:"telco_money",             needs:["telco","money"],                     score:20, label:"Telco + beneficio",                    family:"telco_service_scam",         isManipulation:true,
    detail:"Usa servicio de línea o beneficios para empujar una acción o validación." },
];

// ─── SCAM PATTERN LABELS ──────────────────────────────────────────────────────
// Depurado: clave duplicada `subtle_account_verification` eliminada.

const SCAM_LABELS = {
  bank_credential_scam:      { label:"Suplantación de cuenta o banca",          desc:"Intenta que verifiques acceso, credenciales o datos de cuenta." },
  delivery_courier_scam:     { label:"Estafa de entrega o courier",             desc:"Usa un paquete, entrega o cargo pendiente para empujarte a actuar." },
  boss_impersonation:        { label:"Suplantación de jefe o autoridad",        desc:"Usa urgencia y autoridad implícita para lograr obediencia rápida." },
  tech_support_scam:         { label:"Soporte o seguridad falsa",               desc:"Se presenta como soporte para que hagas algo riesgoso." },
  otp_mfa_scam:              { label:"Robo de código u OTP",                    desc:"Quiere llevarte a compartir o validar códigos sensibles." },
  reward_scam:               { label:"Premio, recarga o beneficio sospechoso",  desc:"Promete un beneficio o premio para que actúes sin verificar." },
  government_tax_fine_scam:  { label:"Multa, deuda o trámite oficial falso",    desc:"Usa lenguaje institucional para empujar pago, validación o miedo." },
  romance_loan_scam:         { label:"Romance o préstamo emocional",            desc:"Usa cercanía para pedir dinero o datos." },
  soft_account_validation:   { label:"Validación suave de cuenta",              desc:"Usa tono institucional y continuidad del servicio para obtener datos." },
  emotional_manipulation:    { label:"Manipulación emocional",                  desc:"Usa presión o consecuencias negativas para empujar una acción." },
  telco_service_scam:        { label:"Estafa de servicio de línea",             desc:"Usa saldo, portabilidad o beneficios para hacerte actuar." },
  threat_credential_combo:   { label:"Amenaza + acción de cuenta",              desc:"Combina miedo a consecuencias con petición de datos o acceso." },
  commercial_scam:           { label:"Spam comercial o scam clásico",           desc:"Lenguaje típico de spam o estafas conocidas." },
  // Modos específicos
  popup_scareware:           { label:"Soporte técnico falso o scareware",       desc:"Usa miedo técnico o bloqueo para hacerte llamar o entrar a un enlace." },
  phone_scam_url:            { label:"Enlace técnico con teléfono sospechoso",  desc:"El link mezcla infraestructura rara con un número de teléfono o soporte falso." },
  fake_job_scam:             { label:"Oferta laboral sospechosa",               desc:"Promete trabajo fácil o dinero alto con señales poco profesionales." },
  upfront_fee_job:           { label:"Estafa laboral con cobro",                desc:"La supuesta vacante pide dinero para avanzar, registrarte o equiparte." },
  marketplace_escrow_scam:   { label:"Liberación de pago o escrow sospechoso", desc:"Usa pago reservado o protegido para hacerte confirmar o liberar operación." },
  social_media_account_takeover: { label:"Robo de cuenta en redes sociales",   desc:"Busca que compartas un código para tomar control de una cuenta." },
  crypto_wallet_scam:        { label:"Estafa de wallet o cripto",               desc:"Pide firmar, conectar wallet o validar frases para tomar control de activos." },
};

// ─── EJEMPLOS DE PRÁCTICA ─────────────────────────────────────────────────────

const PRACTICE_EXAMPLES = [
  // 1. CRÍTICO: phishing de credenciales Microsoft — URL falsa
  `Asunto: Tu clave de Microsoft 365 expira hoy

Tu contraseña de Microsoft 365 expira hoy. Para mantener el acceso activo, actualiza tus credenciales lo antes posible.

hxxps://microsoft-auth-reset.secure-userportal.net

Equipo de TI`,

  // 2. SIN RIESGO: newsletter legítimo ZDNet
  `Asunto: Newsletter semanal — ZDNet

Hola,

Este newsletter fue publicado por ZDNet. Puedes verlo en el navegador, gestionar tus preferencias o darte de baja de esta lista en cualquier momento.

Resumen de esta semana: nuevas herramientas de seguridad, empleos destacados y artículos recomendados de la industria.`,

  // 3. BAJO: comprobante de pago legítimo — sin señales de fraude
  `Banco Santander - Comprobante de pago

Se realizó un pago de $15.490 desde tu cuenta con tarjeta terminada en 8821.
Comercio: Farmacia Cruz Verde
Fecha: 15/03/2025

Si no reconoces esta operación, ignora este mensaje o visita santander.cl.`,

  // 4. MEDIO: solicitud sospechosa de código — señales leves
  `Hola, soy Camila de RRHH. Necesito que me pases el código que te llegó al celular para verificar el sistema de sueldos de este mes. Gracias.`,
];

const MODE_EXAMPLES = {
  auto:        PRACTICE_EXAMPLES,
  email:       [PRACTICE_EXAMPLES[0]],
  sms:         ["URGENTE: Detectamos actividad inusual en tu banca móvil. Verifica tu cuenta y tu código OTP ahora en http://bit.ly/abc123"],
  chat:        ["Hola, cambié de número. Estoy en reunión y no puedo hablar. Haz la transferencia y te explico después."],
  fake_job:    ["Se necesita asistente remoto. Gana $5.000 por semana. No se requiere experiencia. Postula ahora escribiendo a recruiterfastjob@gmail.com"],
  url:         ["https://micro-deskto.azurewebsites.net/0EDhdfgdsjfkjsdhfjksdhNN1/?phone=+1-844-288-8665"],
  popup:       ["Virus detectado. Alerta de soporte de Microsoft. Navegador bloqueado. Llame ahora al +1-844-288-8665"],
  marketplace: ["Tu pago está reservado. Para liberarlo necesito que confirmes tu identidad en el portal indicado."],
  social:      ["Hola, me bloquearon la cuenta de Instagram. Necesito que votes con el código que te llegará por mensaje."],
};

// ─── SCORING CONFIG ───────────────────────────────────────────────────────────

const THRESHOLDS = {
  email:       { critical:70, high:40, medium:20 },
  sms:         { critical:62, high:30, medium:14 },
  chat:        { critical:60, high:28, medium:12 },
  fake_job:    { critical:62, high:28, medium:14 },
  url:         { critical:68, high:36, medium:15 },
  popup:       { critical:60, high:28, medium:12 },
  marketplace: { critical:60, high:28, medium:12 },
  social:      { critical:58, high:28, medium:12 },
};

// Caps por título: máximo acumulado por categoría para evitar inflación
const SCORE_CAPS = {
  "Autoridad o marca":    10,
  "Ambigüedad":           12,
  "Manipulación":         22,
  "Acción riesgosa":      20,
  "Pago o premio":        24,
  "Entrega o courier":    26,
};

// Descuentos cuando un combo fuerte ya cubre señales individuales
const COMBO_DISCOUNTS = {
  "Credenciales + urgencia":     ["Acción riesgosa","Ambigüedad"],
  "Entrega + acción requerida":  ["Entrega o courier","Acción riesgosa","Ambigüedad"],
  "BEC + urgencia":              ["Fraude corporativo","Urgencia"],
  "BEC + autoridad":             ["Fraude corporativo","Urgencia","Acción riesgosa"],
  "Soporte técnico + acción":    ["Soporte falso","Enlace genérico","Acción riesgosa"],
  "Premio/pago + acción":        ["Pago o premio","Acción riesgosa"],
};

// Agrupaciones para la UI educativa
const EDUCATION_GROUPS = [
  { key:"strong",   ids:["credential","threat"],                    className:"edu-credential", title:"Riesgo fuerte",   explanation:"Pide credenciales, amenaza bloqueo o intenta llevarte a una acción sensible." },
  { key:"pressure", ids:["urgency","action","emotional","bec"],     className:"edu-urgency",    title:"Presión o acción", explanation:"Busca que actúes rápido, obedezcas o hagas algo sin verificar bien." },
  { key:"context",  ids:["ambiguity","template","commercial"],      className:"edu-ambiguity",  title:"Contexto débil",  explanation:"Lenguaje genérico o poco verificable. Señal de plantilla o automatización." },
  { key:"infra",    ids:["domain","brand","otp","tech_support"],    className:"edu-domain",     title:"Infraestructura", explanation:"Hay enlaces, dominios o infraestructura que conviene revisar con lupa." },
  { key:"trust",    ids:["trust_newsletter","trust_sms","trust_chat","trust_job","trust_marketplace","trust_social"],
                                                                    className:"edu-trust",      title:"Señales legítimas", explanation:"Pueden bajar sospecha, pero no prueban por sí solas que el mensaje sea legítimo." },
];

const EDUCATION_LEGEND = [
  ["credential","Credenciales / riesgo fuerte"],
  ["urgency","Urgencia / presión"],
  ["ambiguity","Ambigüedad / plantilla"],
  ["authority","Autoridad / marca"],
  ["domain","Dominio / infraestructura"],
  ["trust","Señales legítimas"],
];


// ═══════════════════════════════════════
// SECCIÓN 2: ENGINE V3.1 (Signal-First + Evasion Resistant)
// ═══════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// NotPhish V3 — ENGINE
// Arquitectura: Signal-First (sin dependencia de clasificación previa)
//
// FLUJO:
//   INPUT → NORMALIZE → GLOBAL DETECTORS → URL DETECTORS
//        → CONTEXT ENRICHER (clasifica para UI, ajusta leve)
//        → CORRELATION ENGINE (combos ponderados)
//        → DEDUPE + CAP → SCORE → FINALIZE
//
// DIFERENCIAS VS V2:
//   - Todos los detectores corren siempre, sin depender del modo inferido
//   - inferMode() ahora es solo un etiquetador secundario (0-15% del score)
//   - CORRELATION ENGINE reemplaza COMBOS declarativos: pondera por coexistencia
//   - Trust signals aplican globalmente (no solo en ciertos "modes")
//   - Score calculado en tres capas: raw signals + correlations + context bonus/malus
//   - Explicabilidad mejorada: cada alerta tiene "why" y "where" listos para UI
// ═══════════════════════════════════════════════════════════════════════════════

// ─── NORMALIZACIÓN ────────────────────────────────────────────────────────────

const SPLIT_FIXES = {
  "ver ify":"verify","sig n in":"sign in","val idacion":"validacion",
  "rev ision":"revision","per fil":"perfil","h oy":"hoy",
  "pass word":"password","log in":"login","ac count":"account",
  "cuen ta":"cuenta","sus pendida":"suspendida","ur gente":"urgente",
  "verifi ca":"verifica","creden ciales":"credenciales","blo queada":"bloqueada",
};

const EXTRA_CONFUSABLES = {
  // Griego y cirílico no cubiertos antes
  "ρ":"r","ν":"n","τ":"t","α":"a","ε":"e","ι":"i","ο":"o","υ":"u","β":"b","γ":"g",
  "δ":"d","ζ":"z","η":"h","κ":"k","λ":"l","μ":"m","π":"p","σ":"s","φ":"f","χ":"c","ψ":"p",
  // Matemáticos
  "𝐚":"a","𝐛":"b","𝐜":"c","𝐝":"d","𝐞":"e","𝐟":"f","𝐠":"g","𝐡":"h","𝐢":"i",
  // Círculo
  "ⓐ":"a","ⓑ":"b","ⓒ":"c","ⓓ":"d","ⓔ":"e","ⓕ":"f","ⓖ":"g","ⓗ":"h","ⓘ":"i",
};

function normalizeText(text) {
  let s = text
    // Unir palabras cortadas con salto de línea (bypass B6)
    .replace(/([a-záéíóúüñ])\n([a-záéíóúüñ])/gi, "$1$2")
    // Quitar puntos entre letras individuales: v.e.r.i.f.i.c.a → verifica (bypass B1)
    .replace(/\b([a-záéíóúüñ])\.((?:[a-záéíóúüñ]\.){2,}[a-záéíóúüñ])\b/gi,
      (_, first, rest) => (first + rest).replace(/\./g,""))
    // Normalizar Unicode
    .normalize("NFKC")
    // Lookalikes del sistema original
    .replace(/[ᴄʜɪʟᴇᴘʀꜱѕɑοоеаіӏ]/g, ch => CONFUSABLES[ch] || ch)
    // Lookalikes nuevos (griego, matemático, círculo)
    .replace(/./gu, ch => EXTRA_CONFUSABLES[ch] || ch)
    // Zero-width y directional
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/g, "")
    .normalize("NFD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    // Mayúsculas alternadas: detectar patrón lOgIn → login (bypass B2)
    // Ya resuelto por toLowerCase(), pero limpiamos residuos
    .replace(/[0135@!]/g, ch => ({0:"o",1:"i",3:"e",5:"s","@":"a","!":"i"})[ch] || ch)
    .replace(/(?<=[a-z])[._\-]{1,3}(?=[a-z])/g, "")
    .replace(/[^a-z0-9:/@.$%#?&=+_\-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  for (const [k,v] of Object.entries(SPLIT_FIXES)) s = s.replaceAll(k, v);
  return s.replace(/\b1(?=ogin\b)/g, "l");
}

// ─── URL / DOMINIO ────────────────────────────────────────────────────────────

function stripUrls(t) { return t.replace(new RegExp(RE.url.source,"gi")," "); }

function extractUrls(text) {
  // Normalizar protocolos con mayúsculas antes de extraer (bypass B2: HtTpS://)
  const normalized = text.replace(/(hxxps?|https?):\/\//gi, m => m.toLowerCase());
  return [...normalized.matchAll(new RegExp(RE.url.source,"gi"))].map(m => {
    const c = m[0].replace(/[.,;:!?)]}$/g,"");
    return c.toLowerCase().startsWith("www.") ? `https://${c}` : c;
  });
}

function normDomain(d) { return d.toLowerCase().replace(/^www\./,"").replace(/\.$/,""); }

function domainFromUrl(url) {
  try { return normDomain(new URL(url.replace(/^hxxp/i,"http")).hostname); }
  catch { return ""; }
}

function regDomain(domain) {
  const labels = domain.toLowerCase().replace(/\.$/,"").split(".");
  return labels.length <= 2 ? labels.join(".") : labels.slice(-2).join(".");
}

function subOf(domain) {
  const root = regDomain(domain);
  return domain === root ? "" : domain.slice(0,-root.length).replace(/\.$/,"");
}

function isAbused(domain) {
  return ABUSED_HOSTING.some(h => domain===h || domain.endsWith(`.${h}`));
}

function domainFlags(domain) {
  const flags = [];
  const tld = domain.split(".").at(-1)||"";
  if (SUSPICIOUS_TLDS.has(tld))          flags.push(`TLD inusual .${tld}`);
  if (domain.startsWith("xn--"))         flags.push("usa punycode");
  if ((domain.match(/-/g)||[]).length>=3) flags.push("demasiados guiones");
  if (domain.length > 42)                flags.push("dominio muy largo");

  // "mezcla números y texto" es señal de phishing en dominios desconocidos,
  // pero los ESPs legítimos usan subdominios numerados como convención técnica:
  //   us8.list-manage.com, em1.sendgrid.net, trackercl1.fidelizador.com
  // Si el dominio base es un ESP conocido, omitir este flag.
  if (/\d/.test(domain.replace(/[.-]/g,"")) && domain.replace(/[.-]/g,"").length > 8) {
    if (!isKnownEsp(domain)) flags.push("mezcla números y texto");
  }

  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain)) flags.push("dirección IP directa");
  const rootWords = regDomain(domain).split(".")[0].split(/[-_.]+/).filter(Boolean);
  const sens = rootWords.filter(w=>SUSPICIOUS_DOMAIN_WORDS.includes(w));
  if (sens.length>=2) flags.push(`palabras sensibles: ${sens.slice(0,3).join(", ")}`);
  return flags;
}

function sensitiveUrlParams(url) {
  const low = url.toLowerCase();
  const found = Object.entries(SENSITIVE_URL_TOKENS)
    .filter(([t])=>low.includes(t)).map(([,r])=>r);
  if (/[#?&][^=\s]*[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(url))
    found.push("contiene email dentro del enlace");
  if (/\/[a-f0-9]{12,}\.html\b/i.test(url))
    found.push("ruta HTML con nombre aleatorio");
  return found;
}

function hasSuspPath(url) {
  try {
    const segs = new URL(url.replace(/^hxxp/i,"http")).pathname.split("/").filter(Boolean);
    return segs.some(s=>s.length>20 && /[a-z]/i.test(s) && /\d/.test(s));
  } catch {
    return url.split("?")[0].split("/").filter(Boolean)
      .some(s=>s.length>20 && /[a-z]/i.test(s) && /\d/.test(s));
  }
}

function extractEmailDomains(text) {
  return [...text.matchAll(new RegExp(RE.email.source,"gi"))].map(m=>normDomain(m[1]));
}

function extractRelayDomains(text) {
  const norm = text.normalize("NFKC").toLowerCase().replace(/\s+/g," ");
  const out = new Set();
  for (const marker of ["a traves de","a través de","via"]) {
    const idx = norm.indexOf(marker);
    if (idx===-1) continue;
    const tail = norm.slice(idx+marker.length, idx+marker.length+220);
    for (const m of tail.matchAll(new RegExp(RE.domain.source,"gi")))
      out.add(normDomain(m[0]));
  }
  return [...out];
}

function extractEntities(text) {
  const out = new Set();
  const add = v => {
    for (const tok of v.split(/[^A-Za-zÁÉÍÓÚÜÑáéíóúüñ0-9]+/)) {
      const n = normalizeText(tok).replace(/\s+/g,"");
      if (!n || ENTITY_STOPWORDS.has(n) || /^\d+$/.test(n)) continue;
      out.add(n);
    }
  };
  for (const m of text.matchAll(/([A-Za-zÁÉÍÓÚÜÑáéíóúüñ0-9 ._\-]{3,48})\s+<?[A-Z0-9._%+\-]+@/gi)) add(m[1]);
  for (const m of text.matchAll(new RegExp(RE.domain.source,"gi")))
    add(regDomain(m[0].toLowerCase()).split(".")[0]);
  // Filtrar entidades que son en realidad nombres de servicios conocidos no-entidades
  const NOT_ENTITIES = new Set([
    "bit","tinyurl","goo","ow","buff","cutt","rebrand","shorturl","www",
    "http","https","hxxp","com","net","org","xyz","top","site","online",
    "mail","email","noreply","info","news","blog",
  ]);
  return [...out].filter(e=>e.length>=3&&e.length<=30&&!NOT_ENTITIES.has(e)).sort();
}

function entityMatchesDomain(entity, domain) {
  const root = regDomain(domain).split(".")[0].replace(/[-_]/g,"");
  const norm = normalizeText(entity).replace(/[^a-z0-9]/g,"");
  return Boolean(norm) && (root.includes(norm) || norm.includes(root));
}

// ─── BÚSQUEDA DE TÉRMINOS ─────────────────────────────────────────────────────

function scanTerms(normText, phrases) {
  const found = new Map();
  for (const phrase of phrases) {
    const norm = normalizeText(phrase);
    if (!norm) continue;
    const escaped = norm.replace(/[.*+?^${}()|[\]\\]/g,"\\$&").replace(/\s+/g,"\\s+");
    if (new RegExp(`(^|[^a-z0-9])${escaped}([^a-z0-9]|$)`,"i").test(normText))
      found.set(norm, phrase);
  }
  return [...found.values()].sort();
}

// ─── CONSTRUCCIÓN DE ALERTAS ──────────────────────────────────────────────────

function makeAlert(category, title, detail, severity, opts={}) {
  // Auto-derivar isWeak desde el lookup global si no viene explícito en opts.
  // Así los detectores especiales (detectBec, detectOtp, etc.) también propagan isWeak
  // aunque no lo reciban como parámetro.
  const family = opts.family || category;
  const familyIsWeak = (typeof WEAK_SIGNAL_FAMILIES !== "undefined")
    && WEAK_SIGNAL_FAMILIES.has(family);
  return {
    category, title, detail, severity,
    key:            opts.key            || `${category}:${title}`,
    family:         family,
    isThreat:       opts.isThreat       || false,
    isManipulation: opts.isManipulation || false,
    isTrust:        opts.isTrust        || severity < 0,
    isWeak:         opts.isWeak !== undefined ? opts.isWeak : familyIsWeak,
    why:            opts.why            || detail,
    advice:         opts.advice         || "",
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// GLOBAL DETECTORS — corren siempre, sin importar el tipo de mensaje
// ═══════════════════════════════════════════════════════════════════════════════

function detectSignals(normText) {
  const alerts = [];
  for (const rule of SIGNAL_RULES) {
    // Trust signals aplican globalmente (antes solo aplicaban a ciertos modos)
    // Respetar campo exclude: si algún término de exclusión está en el texto, saltar
    if (rule.exclude && rule.exclude.some(ex => normText.includes(normalizeText(ex)))) continue;
    const found = scanTerms(normText, rule.terms);
    if (!found.length) continue;
    const sev = rule.score < 0
      ? rule.score
      : Math.min(30, rule.score + Math.max(0, found.length - 1) * 2);
    const sample = found.slice(0,5).join(", ") + (found.length>5 ? ` +${found.length-5}` : "");
    alerts.push(makeAlert(rule.label, rule.label, `Encontrado: ${sample}`, sev, {
      key:            `signal:${rule.id}`,
      family:         rule.id,
      isThreat:       rule.isThreat       || false,
      isManipulation: rule.isManipulation || false,
      isTrust:        rule.isTrust        || false,
      isWeak:         rule.isWeak         || false,   // ← NEW: señal débil, no mostrar sola
      why:            rule.explanation    || `Señal de tipo "${rule.label}" detectada.`,
      advice:         rule.advice         || "",
    }));
  }
  return alerts;
}

// ─── URL DETECTORS ────────────────────────────────────────────────────────────

// Verifica si un dominio pertenece a la lista oficial de una marca.
// Acepta subdominios: view.corp.bancofalabella.com → bancofalabella.com en official → OK
// Generalizable: no depende de ninguna marca específica.
function isOfficialDomain(dom, officialList) {
  return officialList.some(g => dom === g || dom.endsWith("." + g) || regDomain(dom) === g);
}

function detectSingleUrl(url) {
  const alerts = [];
  const domain = domainFromUrl(url);
  if (!domain) {
    alerts.push(makeAlert("URL","URL malformada",`No interpretable: ${url}`,8,{family:"bad_url",isThreat:true,why:"El enlace no tiene formato válido."}));
    return alerts;
  }

  if (/^hxxp/i.test(url))
    alerts.push(makeAlert("URL","URL ofuscada",`Usa hxxp para ocultar el destino.`,16,{key:`url:obf:${domain}`,family:"obfuscated_url",isThreat:true,why:"hxxp/hxxps es una técnica para ocultar URLs en reportes y emails falsos."}));

  if (SHORTENERS.has(domain))
    alerts.push(makeAlert("URL","Acortador de URL",`${domain} oculta el destino real.`,18,{key:`url:short:${domain}`,family:"url_shortener",isThreat:true,why:"Los acortadores esconden adónde va el enlace realmente."}));

  if (isAbused(domain))
    alerts.push(makeAlert("URL","Hosting público abusado",`${domain} es infraestructura legítima usada frecuentemente para phishing.`,20,{key:`url:abused:${domain}`,family:"infra_abuse",isThreat:true,why:"Servicios como Azure, Firebase o Netlify son gratuitos y fáciles de usar para alojar páginas de phishing."}));

  const sensParams = sensitiveUrlParams(url);
  if (sensParams.length)
    alerts.push(makeAlert("URL","URL con parámetros sensibles",`${domain}: ${sensParams.join(", ")}.`,Math.min(32,16+sensParams.length*5),{key:`url:sens:${domain}`,family:"sensitive_url",isThreat:true,why:"Los parámetros de la URL contienen tokens, sesiones o datos de autenticación."}));

  const flags = domainFlags(domain);
  if (flags.length)
    alerts.push(makeAlert("URL","Dominio sospechoso",`${domain}: ${flags.join(", ")}.`,Math.min(22,8+flags.length*4),{key:`url:dom:${domain}`,family:"suspicious_domain",isThreat:true,why:"El dominio tiene características técnicas asociadas a infraestructura de phishing."}));

  const sub = subOf(domain);
  // subDomainLegit: subdominios seguros explícitos
  const subDomainLegit = new Set(["accounts.google.com","mail.google.com","login.microsoftonline.com","auth.apple.com","secure.paypal.com","account.live.com","myaccount.google.com","myaccounts.google.com"]);
  if (sub && SUSPICIOUS_SUBDOMAIN_WORDS.some(w=>sub.includes(w)) && !subDomainLegit.has(domain)) {
    // Fix: no marcar como "subdominio engañoso" si el registered domain pertenece a una marca oficial.
    // billing.hostgator.cl, myaccount.google.com, etc. son subdominios del propio dominio oficial.
    const subIsOwnOfficial = Object.values(BRAND_DOMAINS)
      .some(official => official.some(g => regDomain(domain) === g || domain.endsWith("." + g)));
    if (!subIsOwnOfficial)
      alerts.push(makeAlert("URL","Subdominio engañoso",`${domain}: el subdominio usa palabras de confianza, pero el dominio real es ${regDomain(domain)}.`,24,{key:`url:sub:${domain}`,family:"misleading_subdomain",isThreat:true,why:"verify.banco-real.com parece oficial, pero el dominio verdadero es banco-real.com, que no es el banco."}));
  }

  for (const [lookalike,brand] of Object.entries(LOOKALIKE_HINTS))
    if (domain.includes(lookalike))
      alerts.push(makeAlert("URL","Dominio imitador",`${domain} imita a ${brand}.`,26,{key:`url:look:${domain}`,family:"lookalike_domain",isThreat:true,why:`El dominio está diseñado para confundirse con ${brand}.`}));


  for (const [brand,official] of Object.entries(BRAND_DOMAINS)) {
    if (!domain.includes(brand)) continue;
    // isOfficialDomain acepta subdominios del brand (view.corp.bancofalabella.com → bancofalabella.com → OK)
    if (!isOfficialDomain(domain, official))
      alerts.push(makeAlert("URL","Marca en dominio no oficial",`${domain} usa la marca '${brand}' pero no es su dominio oficial.`,35,{key:`url:brand:${domain}`,family:"brand_domain_spoof",isThreat:true,why:`El dominio contiene '${brand}' pero no pertenece a esa empresa.`}));
  }

  if (hasSuspPath(url))
    alerts.push(makeAlert("URL","Ruta aleatoria sospechosa",`${domain} tiene una ruta con caracteres aleatorios.`,12,{key:`url:path:${domain}`,family:"random_path",isThreat:true,why:"Las rutas largas y aleatorias se usan para tracking de víctimas específicas."}));

  return alerts;
}

function detectUrls(urls, bodyNorm, senderDoms) {
  const alerts = urls.flatMap(u => detectSingleUrl(u));

  // Brand mismatch: marca en cuerpo pero dominio del enlace no es oficial.
  //
  // Regla: NO activar brand_link_spoof si:
  //   A) El remitente es un retailer reconocido (ya vende esa marca)
  //   B) O todos los links van al dominio del remitente o a su ESP de tracking
  //   C) O el remitente es una PLATAFORMA legítima que cita marcas en contexto informativo
  //      (LinkedIn jobs citan "empresa Apple", Google alerts citan "dispositivo Apple")
  //
  // SÍ activar si el link va a un dominio desconocido sin relación con el remitente.

  const senderIsRetailer = (senderDoms||[]).some(d =>
    [...KNOWN_RETAILER_SENDERS].some(rd => d === rd || d.endsWith("." + rd) || rd.includes(d))
  );
  // Plataforma legítima: su sender domain está en BRAND_DOMAINS como marca reconocida
  const senderIsPlatform = (senderDoms||[]).some(d =>
    Object.values(BRAND_DOMAINS).some(official => isOfficialDomain(d, official))
  );

  // Detectar footer social (misma lógica que brand_content_spoof)
  const socialInBody2 = [...SOCIAL_FOOTER_BRANDS].filter(b => bodyNorm.includes(b));
  const hasSocFooter2 = socialInBody2.length >= 2 ||
    (socialInBody2.length >= 1 &&
     SOCIAL_FOOTER_CONTEXT.some(ctx => bodyNorm.includes(normalizeText ? normalizeText(ctx) : ctx.toLowerCase())));

  if (!senderIsRetailer && !senderIsPlatform) {
    // Extraer los registeredDomains de los links para comparar con el sender
    const senderRegDoms = new Set((senderDoms||[]).map(d => regDomain(d)).filter(Boolean));

    for (const [brand, official] of Object.entries(BRAND_DOMAINS)) {
      if (!bodyNorm.includes(brand)) continue;
      // No activar para redes sociales en footer de newsletter
      if (SOCIAL_FOOTER_BRANDS.has(brand) && hasSocFooter2) continue;
      for (const url of urls) {
        const dom = domainFromUrl(url);
        if (!dom) continue;
        // isOfficialDomain acepta subdominios del brand (view.corp.bancofalabella.com → OK)
        const isOff = isOfficialDomain(dom, official);
        if (isOff) continue;  // link al dominio oficial de la marca → OK

        // ¿El link va al propio dominio del remitente (o a su subdominio de ESP)?
        // Lógica generalizable: si el regDomain del link == regDomain de algún sender,
        // es un subdominio corporativo propio → no es brand_link_spoof.
        // También: si el subdominio del link empieza con el nombre del sender (ESP tracking).
        const linkRegDom = regDomain(dom);
        const linkIsRetailerEsp = senderRegDoms.size > 0 && [...senderRegDoms].some(srd => {
          const senderLabel = srd.split(".")[0];  // "pcfactory" de "pcfactory.cl"
          return dom === srd
            || dom.endsWith("." + srd)
            || linkRegDom === srd              // view.corp.bancofalabella.com → bancofalabella.com
            || dom.startsWith(senderLabel + ".");  // pcfactory.us8.list-manage.com
        });

        if (!linkIsRetailerEsp) {
          alerts.push(makeAlert(
            "Remitente","Marca en texto ≠ dominio del enlace",
            `Menciona '${brand}' pero el enlace va a ${dom}.`, 28,
            { key:`brand_link_mismatch:${brand}:${dom}`, family:"brand_link_spoof",
              isThreat:true,
              why:`El texto usa el nombre de ${brand} para dar confianza, pero el enlace va a otro sitio.` }
          ));
          break;
        }
      }
    }
  }
  return alerts;
}

function detectDomains(domains, label) {
  return domains.flatMap(dom => {
    const alerts = [];
    if (isAbused(dom))
      alerts.push(makeAlert(label,`${label} en hosting público`,`${dom}`,16,{key:`dom:abused:${label}:${dom}`,family:"infra_abuse",isThreat:true,why:"El dominio del remitente usa infraestructura pública, no corporativa."}));
    const flags = domainFlags(dom);
    if (flags.length)
      alerts.push(makeAlert(label,`Dominio de ${label.toLowerCase()} sospechoso`,`${dom}: ${flags.join(", ")}.`,Math.min(22,10+flags.length*4),{key:`dom:susp:${label}:${dom}`,isThreat:true,why:"El dominio del remitente tiene características atípicas."}));
    return alerts;
  });
}

function detectPlaceholders(text) {
  const found = [...new Set([...text.matchAll(new RegExp(RE.placeholder.source,"gi"))].map(m=>m[0]))];
  if (!found.length) return [];
  return [makeAlert("Plantilla","Campos sin reemplazar",`${found.slice(0,6).join(", ")}`,Math.min(20,8+found.length*4),{family:"template",why:"El mensaje tiene marcadores de plantilla sin completar, señal de automatización masiva."})];
}

function detectObfuscation(text) {
  const susp = [...text].filter(ch=>CONFUSABLES[ch]);
  if (!susp.length) return [];
  const sample = [...new Set(susp)].join("").slice(0,10);
  return [makeAlert("Contenido","Caracteres de evasión",`Caracteres sospechosos: ${sample}`,18,{family:"unicode_obfuscation",isThreat:true,why:"Usa caracteres Unicode que parecen letras normales para evadir filtros automáticos."})];
}

// ─── DETECTORES ESPECIALIZADOS (no dependen del modo) ────────────────────────

function detectBec(normText) {
  const alerts = [];
  // BEC semántico: urgencia implícita + petición de acción + no comunicarse.
  // Fix C: excluir contexto newsletter/comercial claro donde "gift card" o "pago"
  // aparecen en contexto de tienda (regalo de cumpleaños, canje de puntos, etc.)
  // El BEC real siempre requiere: urgencia + silencio + instrucción a persona.
  const hasUrgentAction = ["de inmediato","avanza con esto","hazlo de inmediato","apenas puedas","necesito que gestiones"].some(t=>normText.includes(t));
  const hasPrivacy      = ["no puedo hablar","no puedo atender","no llames","estoy en reunion","estoy entre reuniones","despues te explico","luego vemos"].some(t=>normText.includes(t));
  const hasFinancial    = ["transferencia","wire","envio de fondos",
    // gift card solo en BEC si va acompañado de privacidad o urgencia corporativa
    // "compra gift cards" con "no me llames" es BEC; "gift card" en newsletter no
    "compra gift cards","gift cards urgente"].some(t=>normText.includes(t));
  if (hasUrgentAction && hasPrivacy)
    alerts.push(makeAlert("BEC","Urgencia + silencio → fraude corporativo","Pide acción urgente y evita comunicación directa.",40,{family:"boss_impersonation",isThreat:true,isManipulation:true,why:"El atacante mezcla urgencia con aislamiento para evitar que verifiques con la persona real.",advice:"Confirma con esa persona por un canal diferente antes de hacer nada."}));
  if (hasFinancial && hasPrivacy)
    alerts.push(makeAlert("BEC","Dinero + no llamar → BEC clásico","Solicita operación financiera con restricción de comunicación.",32,{family:"boss_impersonation",isThreat:true,isManipulation:true,why:"El patrón de 'hazlo pero no me llames' es la firma del Business Email Compromise.",advice:"Ningún ejecutivo real debería pedirte esto por mensaje."}));
  return alerts;
}

function detectOtp(normText) {
  // Fix: excluir contexto de código COMERCIAL/PROMOCIONAL.
  // "código de descuento", "cupón", "ver código" son normales en e-commerce.
  const hasPromoContext = TERMS.promo_code_context.some(t => normText.includes(normalizeText(t)));

  // OTP solo aplica si hay código numérico de 4-8 dígitos O términos muy específicos de autenticación
  const hasNumericCode     = /\b\d{4,8}\b/.test(normText) || ["otp","one-time","passcode","2fa","two factor"].some(t=>normText.includes(t));
  const hasAuthContext     = !["reserva","vuelo","confirmacion","pedido","order","booking"].some(t=>normText.includes(t));
  const hasOtpRequest      = hasNumericCode && hasAuthContext && !hasPromoContext &&
    ["codigo de verificacion","verification code","otp","one-time","passcode","2fa","two factor",
     "codigo de acceso","codigo de seguridad"].some(t=>normText.includes(t));
  const hasUrgency         = ["ahora","urgente","expira","expires","inmediato","de inmediato"].some(t=>normText.includes(t));
  const hasSend            = ["comparte","compartir","ingresa","ingresar","envia","enviar","proporciona"].some(t=>normText.includes(t));
  const hasShareWithAgent  = ["comparte este codigo","comparte el codigo","envia el codigo","envía el código",
    "proporciona el codigo","danos el codigo","dame el codigo","manda el codigo"].some(t=>normText.includes(t));

  if (hasShareWithAgent)
    return [makeAlert("OTP","Pedido de código OTP a tercero","Pide que compartas un código de verificación con un agente.",40,{family:"otp_mfa_scam",isThreat:true,isManipulation:true,why:"Compartir un OTP es un ataque MitM clásico para tomar control de tu cuenta.",advice:"Nunca compartas un código OTP con nadie, ni con soporte."})];
  if (hasOtpRequest && (hasUrgency || hasSend))
    return [makeAlert("OTP","Solicitud urgente de código OTP","Pide un código de verificación con presión temporal.",30,{family:"otp_mfa_scam",isThreat:true,isManipulation:true,why:"El código OTP es la llave de tu cuenta. Quien lo pide quiere entrar a ella.",advice:"Nunca compartas un código OTP, ni con quien dice ser soporte."})];
  return [];
}

function detectSocialEngineering(normText) {
  const alerts = [];
  // Popup/scareware semántico
  const hasTechFear  = ["virus detectado","malware","infeccion","spyware","dispositivo comprometido","equipo infectado"].some(t=>normText.includes(t));
  const hasTechCall  = ["llame ahora","call now","contacta soporte","contact support","numero de soporte"].some(t=>normText.includes(t));
  if (hasTechFear && hasTechCall)
    alerts.push(makeAlert("Scareware","Miedo técnico + número de soporte","Inventa un virus y ofrece soporte por teléfono.",30,{family:"tech_support_scam",isThreat:true,isManipulation:true,why:"Crear miedo técnico para que llames es el fraude de soporte falso clásico.",advice:"El soporte real nunca aparece en un popup ni te pide llamar."}));
  // Cuenta social robada + pedir acción
  // Fix: distinguir footer con redes sociales (legítimo) de fraude de cuenta social.
  // El fraude real SIEMPRE pide una acción: votar, compartir código, dar acceso.
  // Un newsletter con icons de LinkedIn/Facebook en el footer NO es esto.
  //
  // Regla: activar SOLO si hay señal de problema de cuenta + petición explícita de acción.
  // "instagram" solo, o varias redes juntas sin petición de acción = footer legítimo.
  const hasSocialProblem = [
    "cuenta bloqueada","perfil robado","me hackearon","perdí acceso",
    "no puedo entrar","bloquearon mi","robaron mi cuenta","my account was hacked",
    "account suspended","cuenta suspendida",
  ].some(t=>normText.includes(t));
  const hasSocialActionReq = [
    "vota por mi","votando por mi","dame el codigo","comparte el codigo",
    "manda el codigo","ayudame a recuperar","contacto de confianza",
    "acceso a mi cuenta","help me recover","vote for me",
  ].some(t=>normText.includes(t));
  // Solo activar si hay problema de cuenta Y acción solicitada
  // (no por simple mención de redes sociales en footer)
  if (hasSocialProblem && hasSocialActionReq)
    alerts.push(makeAlert("Social","Cuenta social + código/enlace","Usa problema de cuenta social para pedir código o enlace.",28,{family:"social_media_account_takeover",isThreat:true,isManipulation:true,why:"El atacante finge tener un problema en su cuenta para que le cedas el tuyo.",advice:"No votes, no compartas códigos ni abras links por este tipo de mensaje."}));
  // Cripto
  if (["seed phrase","frase semilla","staking","airdrop","wallet connect","connect wallet","claim tokens"].some(t=>normText.includes(t)))
    alerts.push(makeAlert("Cripto","Estafa de wallet/cripto","Pide frase semilla, conectar wallet o reclamar tokens.",28,{family:"crypto_wallet_scam",isThreat:true,why:"Dar tu seed phrase entrega control total de tu wallet.",advice:"Ninguna app legítima pide tu seed phrase."}));
  // Romance/préstamo
  const hasRomance  = ["estoy varado","hotel","billetera robada","emergencia familiar","viaje de negocios","me robaron"].some(t=>normText.includes(t));
  const hasLoan     = ["prestamo","prestame","transferencia temporal","te devuelvo","wire me"].some(t=>normText.includes(t));
  if (hasRomance && hasLoan)
    alerts.push(makeAlert("Romance","Emergencia + préstamo → romance scam","Usa historia personal urgente para pedir dinero.",24,{family:"romance_loan_scam",isThreat:true,isManipulation:true,why:"Los romance scams siempre tienen una emergencia que requiere dinero urgente.",advice:"Habla con esa persona por videollamada antes de cualquier transferencia."}));
  return alerts;
}

function detectFakeJob(normText, rawText) {
  const alerts = [];
  const isJob = ["trabaja desde casa","work from home","sin experiencia","no se requiere","asistente remoto","reclutador","recruiter","vacante","apply now","postula ahora"].some(t=>normText.includes(t));
  if (!isJob) return [];
  if (/@(gmail|yahoo|outlook|hotmail|protonmail)\.com\b/i.test(rawText))
    alerts.push(makeAlert("Empleo","Recruiter con email personal","Oferta laboral enviada desde correo genérico, no corporativo.",18,{family:"personal_email_recruiter",isThreat:true,why:"Un recruiter real usa el dominio de la empresa, no Gmail."}));
  if (/(usd|eur|clp|\$|€)\s*\d{1,3}(?:[.,]\d{3})*/.test(rawText) && /week|semana|mes|month|dia|day/.test(normText))
    alerts.push(makeAlert("Empleo","Salario llamativo sin contexto","Promete dinero alto en poco tiempo con poca información.",16,{family:"salary_hype",isThreat:true,why:"Las ofertas reales no enfatizan ganancias extraordinarias en el primer mensaje."}));
  const hasFee = ["pagar registro","costo inicial","equipo requerido","deposito","adelanto","pago de certificacion"].some(t=>normText.includes(t));
  if (hasFee)
    alerts.push(makeAlert("Empleo","Cobro para trabajar","La vacante pide dinero para avanzar.",28,{family:"upfront_fee_job",isThreat:true,why:"Ningún empleo legítimo cobra al candidato para contratarlo.",advice:"Si piden dinero para trabajar, es estafa."}));
  return alerts;
}

function detectMarketplace(normText) {
  const isMarket = ["pago retenido","pago liberado","escrow","libera el pago","vendedor verificado","comprador verificado","portal de pago"].some(t=>normText.includes(t));
  if (!isMarket) return [];
  return [makeAlert("Marketplace","Pago retenido/escrow sospechoso","Menciona liberación de pago o portal externo.",24,{family:"marketplace_escrow_scam",isThreat:true,isManipulation:true,why:"El escrow falso es una de las estafas más comunes en compraventa online.",advice:"Las plataformas oficiales no piden confirmar pagos por fuera."})];
}

function detectPhoneInText(rawText) {
  if (RE.phone.test(rawText))
    return [makeAlert("Teléfono","Número de teléfono en el mensaje","El mensaje incluye un número telefónico.",10,{family:"phone_in_message",why:"Los phishing que piden llamar usan el teléfono para controlar mejor la conversación."})]
  return [];
}

// ─── CONTEXT ENRICHER ────────────────────────────────────────────────────────
// Clasifica el mensaje para UI y aplica bonus/malus de 0-15% sobre el score.
// NO determina qué señales se detectan.

const CONTEXT_PATTERNS = [
  { id:"email",       match: t=> ["subject:","from:","asunto:","de:","para:"].some(m=>t.includes(m)) || t.split(/\r?\n/).filter(l=>l.trim()).length>=6,   label:"Correo electrónico",  icon:"✉",  bonus:0 },
  { id:"sms",         match: t=> t.length<220 && /otp|recarga|saldo|customer care|kyc|txtStop/i.test(t),                                                   label:"SMS",                 icon:"📱", bonus:0 },
  { id:"popup",       match: t=> /virus detected|call now|microsoft support|apple support|browser locked|navegador bloqueado/i.test(t),                     label:"Popup / Alerta",     icon:"⚠", bonus:5 },
  { id:"fake_job",    match: t=> /recruiter|apply now|salary|sin experiencia|asistente remoto|trabajo remoto/i.test(t),                                     label:"Oferta de empleo",   icon:"💼", bonus:0 },
  { id:"marketplace", match: t=> /pago retenido|liberar el pago|escrow|validar vendedor/i.test(t),                                                          label:"Compraventa",         icon:"🛒", bonus:0 },
  { id:"social",      match: t=> /instagram|facebook|contacto de confianza|seed phrase|staking|airdrop/i.test(t),                                           label:"Red social",          icon:"🔗", bonus:0 },
  { id:"url",         match: t=> t.split(/\r?\n/).filter(l=>l.trim()).length<=2 && /^https?:\/\//i.test(t.trim()),                                           label:"URL",                 icon:"🌐", bonus:3 },
  { id:"chat",        match: t=> /cambi[eé] de n[úu]mero|transfi[eé]reme|mandame dinero|bizum/i.test(t),                                                    label:"Chat / WhatsApp",    icon:"💬", bonus:0 },
];

function enrichContext(rawText) {
  for (const p of CONTEXT_PATTERNS)
    if (p.match(rawText)) return p;
  return { id:"email", label:"Mensaje", icon:"📋", bonus:0 };
}

// Consejos específicos por contexto
// Boosters específicos por familia + señal
// Si fake_job tiene cobro, es crítico automáticamente
// Esto se resuelve subiendo el score de "upfront_fee_job" detector
// (ya definido en detectFakeJob) de 28 a 38

const CONTEXT_ADVICE = {
  email:       "Verifica el dominio completo del remitente, no solo el nombre.",
  sms:         "Los SMS legítimos de tu banco nunca piden credenciales.",
  popup:       "Cierra el popup. El soporte real nunca aparece así.",
  fake_job:    "Busca la empresa en fuentes independientes antes de responder.",
  marketplace: "Usa solo los canales de pago de la plataforma oficial.",
  social:      "No compartas códigos aunque el contacto parezca conocido.",
  url:         "Compara el dominio real con el sitio oficial que conoces.",
  chat:        "Si no esperabas este mensaje, confirma por llamada antes de actuar.",
};

// Lookup rápido: familia → isWeak (derivado de SIGNAL_RULES + familias conocidas)
// Usado por hybrid.js para filtrar señales débiles de la UI.
const WEAK_SIGNAL_FAMILIES = new Set([
  // De SIGNAL_RULES marcados como isWeak
  "urgency","authority","ambiguity","action","delivery","money","emotional",
  "government","otp","telco","commercial","officiality",
  // phone_in_message: número de teléfono en texto es señal contextual, no hard
  // Solo activa como hard en combinación (scareware_phone_combo, bec, etc.)
  "phone_in_message",
  // Correlaciones derivadas de weak-only
  "gov_money_combo","government_tax_fine_scam","emotional_action_combo",
  "soft_account_combo",
]);


// ─── CORRELATION ENGINE ───────────────────────────────────────────────────────
// Detecta coexistencia de familias y añade un bonus de correlación.
// Más flexible que COMBOS declarativos: no requiere coincidir exactamente.

const CORRELATIONS = [
  // [familias_requeridas, scoreBonus, label, family, isThreat, isManip, why]
  [["credential","urgency"],       26,"Credenciales bajo presión temporal",   "phishing_credential_urgency",true,true, "Pedir datos de acceso con prisa es el núcleo del phishing bancario."],
  [["delivery","action"],          24,"Entrega bloqueada + acción requerida", "delivery_action_combo",       true,true, "El paquete retenido es señuelo; la acción es lo que busca el atacante."],
  [["authority","credential"],     24,"Autoridad + validación de acceso",     "authority_credential_combo",  true,true, "Imitar una marca para pedir credenciales es suplantación clásica."],
  [["boss_impersonation","urgency"],40,"BEC con urgencia",                    "bec_urgency_combo",           true,true, "La urgencia hace que la víctima actúe sin verificar."],
  [["boss_impersonation","authority"],35,"BEC con autoridad",                 "bec_authority_combo",         true,true, "Combina jerarquía y urgencia para lograr obediencia."],
  [["tech_support_scam","action"],  24,"Soporte falso + acción",              "tech_action_combo",           true,false,"Miedo técnico más instrucción de acción es el patrón de scareware."],
  [["threat","action"],             24,"Amenaza + acción de cuenta",          "threat_action_combo",         true,true, "Bloquear el acceso y pedir que actúes es presión máxima."],
  [["money","action"],              24,"Premio/pago + acción",                "money_action_combo",          true,false,"Los premios que requieren acción buscan datos o dinero."],
  [["romance_loan_scam","money"],   22,"Historia personal + dinero",          "romance_money_combo",         true,true, "La cercanía emocional se usa para bajar la guardia antes de pedir dinero."],
  [["government","money"],          24,"Entidad pública + cobro",             "gov_money_combo",             true,false,"Multas o deudas gubernamentales falsas se usan para extorsionar."],
  [["otp_mfa_scam","urgency"],      32,"OTP urgente",                         "otp_urgency_combo",           true,true, "Urgencia + código OTP = robo de cuenta en tiempo real."],
  [["url_shortener","urgency"],      20,"Acortador + urgencia","shortener_urgency_combo",true,true,"Enlace acortado con presión temporal."],
  [["url_shortener","credential"],   22,"Acortador + credenciales","shortener_cred_combo",true,true,"Acortador que lleva a formulario de credenciales."],
  [["otp_mfa_scam","url_shortener"], 24,"OTP + acortador de URL",                "otp_shortener_combo",         true,true, "Código OTP solicitado a través de un enlace acortado: señal fuerte de phishing."],
  [["social_media_account_takeover","otp_mfa_scam"],18,"Cuenta social + OTP","social_otp_combo",true,true,"Cuenta social bloqueada + pedido de código: patrón de robo de cuenta en redes sociales."],
  [["brand_domain_spoof","credential"],35,"Dominio imitador + credenciales",  "brand_cred_combo",            true,true, "El dominio falso convierte la página en trampa perfecta."],
  [["infra_abuse","suspicious_domain"],18,"Hosting abusado + dominio dudoso", "infra_domain_combo",          true,false,"Doble señal de infraestructura de phishing."],
  [["emotional","action"],          16,"Presión emocional + acción",          "emotional_action_combo",      false,true,"La emoción reduce el pensamiento crítico antes de una acción riesgosa."],
  [["ambiguity","credential"],      20,"Lenguaje vago + credenciales",        "soft_account_combo",          true,true, "El contexto impreciso más petición de acceso es señal de phishing suave."],
  [["authority","suspicious_domain"], 22,"Autoridad + dominio sospechoso","auth_domain_combo",true,true, "Suplantación de marca con dominio sospechoso."],
  [["urgency","suspicious_domain"], 26,"Urgencia + dominio sospechoso",       "urgency_domain_combo",        true,true, "Texto urgente que lleva a dominio dudoso es la estructura básica del phishing."],
  [["credential","suspicious_domain"],28,"Credenciales + dominio sospechoso","cred_domain_combo",           true,true, "Pedir acceso desde un dominio dudoso: patrón central de phishing de credenciales."],
  [["romance","urgency"],           28,"Romance + urgencia",                  "romance_urgency_combo",       true,true, "La urgencia en el contexto de romance/préstamo acelera el fraude emocional."],
  [["romance_loan_scam","urgency"],  30,"Emergencia romántica con urgencia",   "romance_emerg_urgency",       true,true, "Historia de emergencia combinada con urgencia temporal para presionar la transferencia."],
  [["romance_loan_scam","money"],    32,"Emergencia romántica con dinero",     "romance_emerg_money",         true,true, "Historia personal urgente combinada con petición de dinero."],
  [["romance","money"],             38,"Romance + dinero",                    "romance_money_combo",         true,true, "Cercanía emocional + petición de dinero = romance scam clásico."],
  [["investment_scam","money"],     22,"Inversión + dinero",
  [["upfront_fee_job","salary_hype"], 30,"Fake job: cobro + sueldo llamativo","upfront_salary_combo",true,false,"Cobro de inscripción más promesa de sueldo alto es la firma del fake job."],
  [["upfront_fee_job","personal_email_recruiter"], 20,"Fake job: cobro + email personal","upfront_email_combo",true,false,"Recruiter con email genérico que pide cobro: 100% fake job."],
  [["upfront_fee_job","money"],      30,"Fake job: cobro + dinero",           "upfront_money_combo",        true,false,"Hacer pagar para trabajar combinado con promesas de dinero es fraude laboral."],                  "invest_money_combo",          true,false,"Combinar promesas de inversión con lenguaje de pago es señal fuerte de fraude."],
  [["money_mule_scam","authority"], 22,"Mula de dinero + autoridad",         "mule_authority_combo",        true,false,"El esquema de mula se presenta como empresa legítima con oportunidad de trabajo."],
  [["popup_scareware","phone_in_message"],20,"Scareware + teléfono",          "scareware_phone_combo",       true,true, "La combinación de alerta técnica con número de soporte es firma del tech support scam."],
  // PHI04: GDPR/legal phishing en hosting público
  [["ambiguity","infra_abuse"],       20,"Lenguaje vago + hosting abusado",       "ambiguity_infra_combo",       true,true, "Contexto impreciso combinado con hosting público: estructura típica de phishing genérico."],
  [["threat","infra_abuse"],          22,"Amenaza de bloqueo + hosting abusado",  "threat_infra_combo",          true,true, "Combina amenaza de suspensión con hosting público de phishing."],
  // ROM: romance_loan_scam específico
  [["romance_loan_scam","urgency"],   30,"Emergencia romántica urgente",          "romance_emerg_urgency",       true,true, "Historia de emergencia con urgencia temporal para presionar la transferencia."],
  [["romance_loan_scam","money"],     32,"Emergencia romántica con dinero",       "romance_emerg_money",         true,true, "Historia personal urgente combinada con petición de dinero."],
  [["romance","money"],              28,"Romance + transferencia de dinero",      "romance_money_transfer",      true,true, "Historia emocional combinada con petición directa de transferencia."],
  [["romance","urgency"],            24,"Romance + urgencia",                     "romance_urgency_direct",      true,true, "Historia emocional con urgencia: patrón de romance scam."],
];

function detectCorrelations(alerts, isReportage=false) {
  const families = new Set(alerts.map(a=>a.family));

  // Mapa family → isWeak para saber si la señal base es débil
  const familyWeakness = new Map(alerts.map(a => [a.family, a.isWeak||false]));

  const correlAlerts = [];
  for (const [needs, score, label, family, isThreat, isManip, why] of CORRELATIONS) {
    if (!needs.every(f => families.has(f))) continue;
    if (isReportage && !["brand_link_spoof","brand_domain_spoof","infra_abuse"].some(f=>needs.includes(f))) continue;

    // Fix: si TODAS las señales requeridas son débiles (isWeak), no generar correlación.
    // Una correlación de débiles no es evidencia fuerte.
    // Ejemplo: government(weak) + money(weak) → gov_money_combo no debe activar en boletas de Movistar.
    const allRequiredAreWeak = needs.every(f => familyWeakness.get(f) === true);
    if (allRequiredAreWeak) continue;

    correlAlerts.push(makeAlert("Correlación", label,
      `Combinación detectada: ${needs.join(" + ")}`, score,
      {key:`corr:${family}`, family, isThreat, isManipulation:isManip, why}
    ));
  }
  return correlAlerts;
}

// ─── DEDUPE + CAP ─────────────────────────────────────────────────────────────

// Caps por categoría: evitan que una sola categoría domine el score
const CATEGORY_CAPS = {
  "Autoridad o marca":    10,
  "Ambigüedad":           12,
  "Señales legítimas":    -999, // trust: sin cap negativo (se acumulan)
  "Acción riesgosa":      22,
  "Pago o premio":        24,
  "Entrega o courier":    26,
  "Manipulación":         22,
};

// Descuentos: si existe una correlación fuerte, las señales individuales que ya
// están cubiertas no deben doble-contar
const CORR_DISCOUNTS = {
  "phishing_credential_urgency": ["credential","urgency"],
  "delivery_action_combo":       ["delivery","action"],
  "bec_urgency_combo":           ["boss_impersonation","urgency"],
  "bec_authority_combo":         ["boss_impersonation","authority","action"],
  "tech_action_combo":           ["tech_support_scam","action"],
  "money_action_combo":          ["money","action"],
};

function dedupeAlerts(alerts) {
  // 1. Dedup por key
  const byKey = new Map();
  for (const a of alerts) {
    const k = a.key||`${a.category}:${a.title}`;
    if (!byKey.has(k) || byKey.get(k).severity < a.severity) byKey.set(k, a);
  }
  const unique = [...byKey.values()];

  // 2. Aplicar descuentos por correlación cubierta
  const corrFamilies = new Set(unique.filter(a=>a.category==="Correlación" && a.severity>=20).map(a=>a.family));
  const discounted   = new Set();
  for (const [cf, covered] of Object.entries(CORR_DISCOUNTS))
    if (corrFamilies.has(cf)) covered.forEach(f=>discounted.add(f));

  // 3. Descuentar alertas cubiertas
  const adjusted = unique.map(a =>
    discounted.has(a.family) ? {...a, severity: Math.max(3, Math.round(a.severity*0.65))} : a
  );

  // 4. Ordenar y aplicar caps por categoría
  const used = {};
  return adjusted
    .sort((a,b) => b.severity - a.severity)
    .map(a => {
      if (a.severity < 0) return a; // trust: siempre pasan
      if (a.category === "Correlación" || !CATEGORY_CAPS[a.category]) return a;
      const cap  = CATEGORY_CAPS[a.category] ?? Infinity;
      const rem  = cap - (used[a.category]||0);
      if (rem <= 0) return {...a, severity:0};
      const sev  = Math.min(a.severity, rem);
      used[a.category] = (used[a.category]||0) + sev;
      return {...a, severity:sev};
    })
    .filter(a => a.severity !== 0);
}

// ─── SCORING ──────────────────────────────────────────────────────────────────

// Umbrales globales (ya no varían por modo — la clasificación es secundaria)
const THRESHOLDS_GLOBAL = { critical:65, high:36, medium:16 };

// Bonus por contexto (max 15 pts) — no varía el umbral, solo ajusta el score
function contextBonus(context) { return context.bonus || 0; }

function scoreAlerts(alerts) {
  const raw    = Math.max(0, alerts.reduce((s,a)=>s+a.severity, 0));
  const threat = Math.min(100, alerts.filter(a=>a.isThreat).reduce((s,a)=>s+Math.max(0,a.severity),0));
  const manip  = Math.min(100, alerts.filter(a=>a.isManipulation).reduce((s,a)=>s+Math.max(0,a.severity),0));
  return { raw, threat, manip };
}

function riskLevel(composite, hasTrust, trustScore) {
  if (composite <= 0) return "Bajo";
  if (hasTrust && trustScore < -8 && composite < THRESHOLDS_GLOBAL.medium) return "Bajo";
  if (composite >= THRESHOLDS_GLOBAL.critical) return "Crítico";
  if (composite >= THRESHOLDS_GLOBAL.high)     return "Alto";
  if (composite >= THRESHOLDS_GLOBAL.medium)   return "Medio";
  return "Bajo";
}

// Etiquetas de usuario para el resumen del resultado
// label: nombre del patrón en lenguaje humano
// desc:  explicación de qué está pasando (para el usuario, no el dev)
const PATTERN_LABELS_USER = {
  // Suplantación de marca / dominio
  brand_domain_spoof:       { label:"Suplantación de marca",        desc:"El enlace imita el nombre de una empresa conocida, pero el dominio es falso. Es una trampa diseñada para robar credenciales." },
  brand_link_spoof:         { label:"Enlace que no corresponde",     desc:"El mensaje usa el nombre de una marca, pero el enlace va a un sitio diferente. Clásica técnica de phishing." },
  brand_content_spoof:      { label:"Suplantación de marca",        desc:"El remitente usa el nombre de una empresa conocida, pero el dominio no pertenece a esa empresa." },
  lookalike_domain:         { label:"Dominio imitador",             desc:"El dominio del enlace está diseñado para confundirse con uno oficial. Revisa cada letra con cuidado." },
  misleading_subdomain:     { label:"Subdominio engañoso",          desc:"El enlace usa palabras de confianza en el subdominio, pero el dominio real es sospechoso." },
  // Infraestructura sospechosa
  suspicious_domain:        { label:"Dominio sospechoso",           desc:"El dominio del enlace tiene características asociadas a sitios de phishing: TLD inusual, nombre muy largo o estructura extraña." },
  infra_abuse:              { label:"Infraestructura pública",       desc:"El enlace usa servicios gratuitos de hosting (Azure, Firebase, etc.) que los atacantes aprovechan para alojar páginas falsas." },
  url_shortener:            { label:"Enlace acortado",              desc:"El enlace usa un acortador que oculta el destino real. No sabes adónde lleva hasta que haces clic." },
  obfuscated_url:           { label:"Enlace ocultado",              desc:"El enlace viene escrito como 'hxxp' para evitar filtros automáticos. Es una señal de mensaje malicioso." },
  // Fraude corporativo BEC
  boss_impersonation:       { label:"Posible fraude corporativo",   desc:"El mensaje usa urgencia y autoridad para que actúes sin verificar. Es el patrón del fraude corporativo (BEC), donde se suplanta a un jefe o proveedor." },
  bec_urgency_combo:        { label:"Fraude corporativo",           desc:"Urgencia extrema combinada con instrucción de acción. El atacante quiere que actúes antes de que puedas verificar." },
  bec_bank_change:          { label:"Cambio de cuenta sospechoso",  desc:"Aviso de cambio de datos bancarios justo antes de un pago. Técnica usada para desviar transferencias." },
  two_stage_bec:            { label:"Posible fraude en dos etapas", desc:"El mensaje busca disponibilidad sin dar detalles. Es el primer paso de un ataque donde el segundo paso pedirá dinero o datos." },
  // Entrega / courier
  delivery_action_combo:    { label:"Estafa de entrega",           desc:"El mensaje usa un paquete retenido como pretexto para que hagas clic, pagues o des datos. El paquete es el anzuelo." },
  delivery_courier_scam:    { label:"Courier falso",               desc:"Phishing que imita a una empresa de envíos para cobrar tasas falsas o robar datos." },
  // Credenciales / acceso
  phishing_credential_urgency:{ label:"Phishing de credenciales",  desc:"Mezcla de urgencia con pedido de acceso o datos. Es la estructura más común del phishing bancario y corporativo." },
  cred_domain_combo:        { label:"Robo de credenciales",        desc:"Dominio sospechoso que pide datos de acceso. El objetivo es que ingreses tu usuario y contraseña en un sitio falso." },
  auth_domain_combo:        { label:"Phishing de credenciales",    desc:"Usa el nombre de una institución conocida combinado con un dominio falso para obtener tus datos de acceso." },
  // OTP
  otp_mfa_scam:             { label:"Robo de código de verificación", desc:"Alguien quiere que compartas o valides un código OTP. Eso le daría acceso directo a tu cuenta." },
  otp_urgency_combo:        { label:"Urgencia para robar código",  desc:"Presión temporal combinada con pedido de código OTP. Técnica para robar cuentas en tiempo real." },
  otp_shortener_combo:      { label:"OTP con enlace sospechoso",   desc:"Código de verificación solicitado a través de un enlace acortado. Señal fuerte de ataque de cuenta." },
  social_otp_combo:         { label:"Robo de cuenta en redes",     desc:"El atacante usa un problema de red social para que le entregues un código que le dará control de tu cuenta." },
  // Romance / préstamo
  romance_loan_scam:        { label:"Estafa de romance o préstamo", desc:"Usa cercanía emocional o una emergencia para pedir dinero. El atacante genera confianza antes de pedir." },
  romance_money_combo:      { label:"Romance + petición de dinero", desc:"Combina historia emocional con pedido de transferencia. Patrón clásico de estafa romántica." },
  // Empleo falso
  upfront_fee_job:          { label:"Estafa de empleo con cobro",  desc:"La supuesta oferta laboral pide dinero para avanzar. Ningún trabajo real cobra al candidato." },
  personal_email_recruiter: { label:"Oferta laboral sospechosa",   desc:"El reclutador usa un correo personal genérico. Las empresas reales usan dominios corporativos." },
  salary_hype:              { label:"Oferta laboral con sueldo irreal", desc:"Promete dinero muy alto con poco esfuerzo y sin experiencia. Señal clásica de fraude laboral." },
  money_mule_scam:          { label:"Esquema de mula de dinero",   desc:"Te piden recibir y reenviar dinero a cambio de comisión. Es lavado de dinero y puede tener consecuencias legales." },
  // Inversión
  investment_scam:          { label:"Inversión fraudulenta",       desc:"Promete retornos garantizados o sin riesgo. Ninguna inversión real garantiza esto. Es una estafa financiera." },
  // Marketplace
  marketplace_escrow_scam:  { label:"Estafa de compraventa",       desc:"Usa un sistema de pago falso para hacerte confirmar o liberar dinero. El comprador o vendedor no es real." },
  marketplace_advance_scam: { label:"Trampa de pago adelantado",   desc:"Pide que pagues algo antes de cerrar la transacción. En compraventa, el que pide primero generalmente no entrega." },
  // Social / Cripto
  social_media_account_takeover:{ label:"Robo de cuenta en redes", desc:"El atacante usa un problema de cuenta para que le entregues acceso o un código de verificación." },
  crypto_wallet_scam:       { label:"Estafa de criptomonedas",     desc:"Pide conectar tu wallet, firmar una transacción o dar tu frase semilla. Eso entrega control total de tus fondos." },
  // Gobierno / impuestos
  government_tax_fine_scam: { label:"Multa o deuda institucional falsa", desc:"Imita a una entidad pública para generar miedo y cobrar multas falsas o robar datos." },
  // Tech support
  tech_support_scam:        { label:"Soporte técnico falso",       desc:"Inventa un problema técnico para que llames a un número o instales algo. El soporte real nunca aparece así." },
  popup_scareware:          { label:"Alerta técnica falsa",        desc:"Popup o mensaje que inventa una amenaza para que llames a soporte. Ciérralo sin hacer nada más." },
  // Vishing / datos directos
  direct_data_harvest:      { label:"Solicitud directa de datos",  desc:"Alguien dice ser de una institución y pide datos sensibles por mensaje. Las instituciones reales nunca hacen esto." },
  // Evasión
  base64_url:               { label:"Enlace ocultado en código",   desc:"El mensaje esconde una URL codificada para evadir filtros. Señal de mensaje construido para engañar." },
  unicode_obfuscation:      { label:"Texto alterado para evadir filtros", desc:"Usa caracteres especiales que parecen normales para esconderse de los detectores." },
  // Genéricos
  shortener_urgency_combo:  { label:"Enlace acortado con urgencia", desc:"Enlace que oculta su destino combinado con presión para actuar. Señal fuerte de phishing." },
  brand_cred_combo:         { label:"Suplantación con trampa de credenciales", desc:"Dominio que imita a una marca y pide datos de acceso. El objetivo es robar tu usuario y contraseña." },
  unknown_short_domain:     { label:"Enlace sospechoso",           desc:"El enlace tiene un dominio muy corto y desconocido con una ruta de aspecto aleatorio. No sabes adónde lleva." },
};

function classifyPattern(alerts) {
  // Solo considerar alertas no-trust con severidad real neta > 0
  const trustFamilies = new Set(alerts.filter(a=>a.isTrust).map(a=>a.family));
  const netScore = alerts.filter(a=>!a.isTrust).reduce((s,a)=>s+Math.max(0,a.severity),0)
    + alerts.filter(a=>a.isTrust).reduce((s,a)=>s+a.severity,0); // trust suma negativo

  // Si el score neto es 0 o negativo, no hay patrón de fraude
  if(netScore <= 0) return {
    label: "Sin señales de fraude",
    desc:  "No detectamos patrones de riesgo en este mensaje."
  };

  // Si TODOS los alerts son señales débiles (isWeak) → no usar etiqueta acusatoria
  const nonTrustAlerts  = alerts.filter(a => a.severity>0 && !a.isTrust);
  const hasHardSignal   = nonTrustAlerts.some(a => !a.isWeak);
  const onlyWeakSignals = nonTrustAlerts.length > 0 && !hasHardSignal;

  if (onlyWeakSignals) {
    // Solo señales débiles — usar lenguaje informativo, no acusatorio
    return {
      label: "Sin evidencia fuerte",
      desc:  "Encontramos palabras que a veces aparecen en mensajes sospechosos, pero sin evidencia técnica clara. El contexto parece normal."
    };
  }

  const ranked = new Map();
  for (const a of alerts) {
    if (!a.family || a.isTrust) continue;
    const w = Math.max(0,a.severity) + (a.isThreat?4:0) + (a.isManipulation?2:0);
    ranked.set(a.family, (ranked.get(a.family)||0)+w);
  }
  const best = [...ranked.entries()].sort((a,b)=>b[1]-a[1])[0]?.[0];
  if (best && PATTERN_LABELS_USER[best]) return PATTERN_LABELS_USER[best];
  if (best && SCAM_LABELS[best]) return SCAM_LABELS[best];
  const hasTrustSignals = alerts.some(a=>a.isTrust);
  if (netScore < 15 && hasTrustSignals) return {
    label: "Mensaje con señales mixtas",
    desc:  "Hay señales que podrían indicar riesgo, pero también indicadores de un mensaje legítimo. Revisa el contexto."
  };
  if (netScore < 20 && !best) return {
    label: "Señales leves",
    desc:  "Detectamos algo que vale la pena revisar, pero no es un patrón claro de fraude."
  };
  const top = [...alerts].filter(a=>a.severity>0&&!a.isTrust).sort((a,b)=>b.severity-a.severity)[0];
  if (top?.why) return { label: top.title, desc: top.why };
  return { label:"Sin patrón claro", desc:"No detectamos un patrón definido, pero revisa el remitente y el contexto antes de actuar." };
}

function buildRecommendations(risk, alerts, urls, context) {
  // Sistema de recomendaciones específicas por familia detectada
  // Objetivo: máximo 4 consejos, todos relevantes al caso concreto, sin repetición

  const families = new Set(alerts.filter(a=>a.severity>0&&!a.isTrust).map(a=>a.family));
  const recs = [];
  const seen = new Set();
  function add(r) { const k=r.trim().toLowerCase(); if(!seen.has(k)&&r.trim()){seen.add(k);recs.push(r.trim());} }

  const hasUrls       = urls.length > 0;
  const hasBec        = families.has("boss_impersonation")||families.has("bec_urgency_combo")||
                        families.has("bec_authority_combo")||families.has("two_stage_bec")||
                        families.has("bec_bank_change")||families.has("direct_data_harvest");
  const hasDelivery   = families.has("delivery_action_combo")||families.has("delivery_courier_scam")||
                        families.has("delivery")||
                        alerts.some(a=>
                          a.family==="delivery"||
                          a.category==="Entrega o courier"||
                          (a.title||"").toLowerCase().includes("paquete")||
                          (a.title||"").toLowerCase().includes("entrega")||
                          (a.title||"").toLowerCase().includes("courier")
                        );
  const hasCredential = families.has("phishing_credential_urgency")||families.has("cred_domain_combo")||
                        families.has("brand_cred_combo")||families.has("auth_domain_combo");
  const hasOtp        = families.has("otp_mfa_scam")||families.has("otp_urgency_combo")||
                        families.has("otp_shortener_combo")||families.has("social_otp_combo");
  const hasRomance    = families.has("romance_loan_scam")||families.has("romance_money_combo")||
                        families.has("romance_money_transfer")||families.has("romance_urgency_direct")||
                        families.has("romance_emerg_money")||families.has("romance_emerg_urgency")||
                        families.has("romance");
  const hasJob        = families.has("upfront_fee_job")||families.has("salary_hype")||
                        families.has("personal_email_recruiter")||families.has("money_mule_scam");
  const hasCrypto     = families.has("crypto_wallet_scam")||families.has("investment_scam");
  const hasMarket     = families.has("marketplace_escrow_scam")||families.has("marketplace_advance_scam");
  const hasSocial     = families.has("social_media_account_takeover");
  const hasTech       = families.has("tech_support_scam")||families.has("popup_scareware");
  const hasDataReq    = families.has("direct_data_harvest");

  // ── Consejo principal según el tipo de amenaza ──────────────────────────
  if (hasBec && !hasUrls) {
    add("Llama directamente a esa persona antes de hacer cualquier cosa. No respondas por el mismo canal.");
    add("Los jefes y proveedores legítimos no piden transferencias urgentes por mensaje sin verificación.");
  } else if (hasDelivery) {
    add("Entra al sitio oficial del courier (chilexpress.cl, starken.cl, etc.) y busca tu número de seguimiento allí.");
    add("Las empresas de envío no cobran tasas aduaneras por SMS ni por enlace — eso siempre se paga en persona o en su app oficial.");
  } else if (hasCredential) {
    const domain = urls.length ? domainFromUrl(urls[0]) : null;
    if (domain) add(`No ingreses tus datos en ${domain}. Ve directamente al sitio oficial desde tu browser.`);
    else add("No ingreses tus credenciales desde este enlace. Ve al sitio oficial directamente.");
    add("Si ya ingresaste tu contraseña, cámbiala ahora desde el sitio oficial.");
  } else if (hasOtp) {
    add("Nunca compartas un código de verificación con nadie — ni soporte, ni contactos conocidos, ni agentes.");
    add("Si ya enviaste el código, cambia tu contraseña y activa verificación en dos pasos desde el sitio oficial.");
  } else if (hasRomance) {
    add("Antes de transferir dinero a alguien que no conoces en persona, habla con un familiar o amigo de confianza.");
    add("Los atacantes siempre tienen una urgencia que no puede esperar. Eso es la señal más importante.");
  } else if (hasJob) {
    add("Ningún trabajo legítimo cobra al candidato para comenzar. Si piden dinero, es una estafa.");
    add("Busca la empresa en fuentes independientes (LinkedIn, sitio oficial) antes de responder.");
  } else if (hasCrypto) {
    const hasCryptoFamily = families.has("crypto_wallet_scam");
    if (hasCryptoFamily) {
      add("Nunca compartas tu frase semilla (seed phrase) con nadie ni la ingreses en ningún sitio.");
      add("Ninguna app o sitio legítimo necesita tu seed phrase para funcionar.");
    } else {
      add("Las inversiones con retornos garantizados no existen. Este es un patrón clásico de fraude financiero.");
      add("Antes de invertir en cualquier cosa, verifica la empresa en el regulador financiero de tu país.");
    }
  } else if (hasMarket) {
    add("Usa únicamente los canales de pago de la plataforma oficial (MercadoPago, Yapo, etc.).");
    add("El que pide pagar primero el flete o una diferencia casi nunca entrega el producto.");
  } else if (hasSocial) {
    add("Nunca compartas un código de verificación aunque quien lo pida parezca un contacto real.");
    add("Si te hackean una cuenta, repórtala directamente desde la app oficial de la red social.");
  } else if (hasTech) {
    add("Cierra la ventana o el mensaje sin llamar a ningún número. El soporte técnico real nunca contacta así.");
  } else if (hasDataReq) {
    add("Las instituciones legítimas nunca piden datos bancarios, RUT ni contraseñas por mensaje.");
    add("Llama tú al número oficial de la institución para verificar antes de dar cualquier dato.");
  } else if (hasUrls) {
    add("No hagas clic en el enlace. Si necesitas acceder al servicio, búscalo directamente en tu browser.");
  } else {
    add("Si tienes dudas, verifica contactando directamente a la institución o persona por un canal conocido.");
  }

  // ── Consejo de dominio (solo si hay URL sospechosa) ─────────────────────
  if (hasUrls && !hasBec && !hasDelivery) {
    const suspDomain = urls.map(domainFromUrl).filter(Boolean)
      .find(d => !["bit.ly","t.co","tinyurl.com","google.com","microsoft.com"].includes(d));
    if (suspDomain) add(`Revisa el dominio completo del enlace: "${suspDomain}". Si no es el sitio oficial que conoces, no entres.`);
  }

  // ── Consejo de daño hecho (solo para riesgo alto/crítico) ───────────────
  if ((risk==="Crítico"||risk==="Alto") && (hasCredential||hasOtp||hasRomance)) {
    add("Si ya interactuaste — hiciste clic, diste datos o transferiste dinero — contacta a tu banco inmediatamente.");
  }

  // ── Recordatorio final universal ────────────────────────────────────────
  if (recs.length < 2) {
    if (risk === "Bajo") {
      add("Si algo te generó duda, para y verifica antes de actuar. Siempre es mejor preguntar.");
    } else {
      add("Cuando tengas dudas, para y verifica. Una pausa de 5 minutos puede evitar un fraude.");
    }
  }

  return recs.slice(0, 4); // máximo 4 consejos
}

// ─── FUNCIÓN PRINCIPAL: ANALYZE ───────────────────────────────────────────────
// Punto de entrada único. No importa el tipo de mensaje.


// ─── DETECTOR: CAMBIO DE DATOS BANCARIOS (BEC de proveedor) ─────────────────
function detectBankChangeScam(normText) {
  const hasChange   = ["cuenta bancaria ha cambiado","cuenta bancaria cambio","cuenta bancaria cambió","cambio de cuenta","nueva cuenta bancaria","cuenta ha cambiado","datos bancarios cambiaron","nueva cuenta para pagos","cambiamos de banco","cambio de banco","cuenta cambio","nuestra cuenta cambio","nuestra cuenta bancaria","cambiamos de cuenta","nuestra cuenta bancaria cambio","cuenta bancaria cambio"].some(t=>normText.includes(t));
  const hasAmount   = /\$\s*[\d.,]+|[\d.,]+\s*pesos|[\d.,]+\s*clp/i.test(normText);
  const hasSilence  = ["no confirmar","no consultar","proceso de auditoria","auditoria interna","no comentar","no mencionar","no confirmen con nadie","hay auditoria","hay auditoría","en auditoria","no lo comenten"].some(t=>normText.includes(t));
  if (hasChange && (hasAmount || hasSilence))
    return [makeAlert("BEC","Cambio de cuenta bancaria sospechoso",
      "Anuncia cambio de datos bancarios justo antes de un pago, con pedido de discreción.",
      36,{family:"bec_bank_change",isThreat:true,isManipulation:true,
        why:"El BEC de proveedor clásico cambia datos bancarios justo antes del pago. La petición de no verificar es la señal más fuerte.",
        advice:"Llama al proveedor por el número que tenías antes de cualquier transferencia."})];
  return [];
}

// ─── DETECTOR: INVERSIÓN / SCAM FINANCIERO ───────────────────────────────────
function detectInvestmentScam(normText) {
  const hasInvest  = ["invertir","inversion","inversión","oportunidad de inversion","oportunidad de inversión","retorno","rendimiento","ganancia garantizada"].some(t=>normText.includes(t));
  const hasGuarant = ["garantizado","sin riesgo","100% seguro","rentabilidad asegurada","retorno fijo","no puedes perder","inversion segura"].some(t=>normText.includes(t));
  const hasHighReturn = /\d+\s*%\s*(mensual|diario|semanal|anual)/i.test(normText);
  if (hasInvest && (hasGuarant || hasHighReturn))
    return [makeAlert("Inversión","Promesa de inversión garantizada",
      "Ofrece retornos garantizados o sin riesgo, patrón de scam financiero.",
      34,{family:"investment_scam",isThreat:true,
        why:"Ninguna inversión real garantiza retornos. Las promesas de alto rendimiento sin riesgo son estafas.",
        advice:"Desconfía de cualquier inversión que prometa ganancias garantizadas."})];
  return [];
}

// ─── DETECTOR: MONEY MULE ────────────────────────────────────────────────────
function detectMoneyMule(normText) {
  const hasProcess = ["procesar pagos","procesar transferencias","recibir pagos","recibir transferencias"].some(t=>normText.includes(t));
  const hasForward = ["reenviar","transferir al","enviar a","descontando tu comision","descontando comision","descuentas tu parte"].some(t=>normText.includes(t));
  const hasComm    = ["comision","comisión","tu porcentaje","tu ganancia","quedate con"].some(t=>normText.includes(t));
  if ((hasProcess || hasForward) && hasComm)
    return [makeAlert("Fraude","Esquema de mula de dinero",
      "Pide recibir dinero en tu cuenta y reenviarlo, a cambio de comisión.",
      38,{family:"money_mule_scam",isThreat:true,
        why:"Las mulas de dinero participan sin saberlo en lavado de activos. Puede resultar en consecuencias legales.",
        advice:"Nunca uses tu cuenta personal para procesar pagos de terceros a cambio de comisión."})];
  return [];
}

// ─── DETECTOR: SCAM DE CAMBIO DE NÚMERO (WhatsApp) ───────────────────────────
function detectNumberChangeScam(normText) {
  const hasChange   = ["cambie de numero","cambié de número","nuevo numero","nueva sim","se me perdio el celular","perdi el celular","robe el celular","cambie de telefono"].some(t=>normText.includes(t));
  const hasRequest  = ["guardalo","guarda el numero","actualiza mi contacto","te escribo desde","escríbeme a este","escribeme a este"].some(t=>normText.includes(t));
  const hasMoneyReq = ["necesito","me ayudas","prestame","préstamo","transferencia","plata","lucas","guita","billete","favor"].some(t=>normText.includes(t));
  if (hasChange && (hasRequest || hasMoneyReq))
    return [makeAlert("Social","Cambio de número + solicitud",
      "Anuncia cambio de número y luego pide algo.",
      28,{family:"changed_number_scam",isManipulation:true,isThreat:true,
        why:"El atacante suplanta a un contacto conocido con un número nuevo para pedir dinero o favores.",
        advice:"Llama al número anterior para verificar antes de actuar."})];
  return [];
}

// ─── DETECTOR: POPUP SCAREWARE MEJORADO ──────────────────────────────────────
function detectPopupScareware(normText, rawText) {
  const hasTechFear = ["virus","malware","infectado","bloqueado","en riesgo","amenaza detectada","alerta de seguridad","ordenador bloqueado","computador bloqueado","datos bancarios en riesgo","no cierre esta ventana"].some(t=>normText.includes(t));
  const hasScareTactic = ["llame ahora","llame de inmediato","llame al","call now","soporte tecnico","soporte técnico","+1-","800-","900-"].some(t=>normText.includes(t));
  const hasEmoji = /[⚠⛔🔴🚨❗]/.test(rawText);
  if (hasTechFear && (hasScareTactic || RE.phone.test(rawText)))
    return [makeAlert("Scareware","Alerta técnica falsa con número de soporte",
      `Usa ${hasEmoji?"emojis de alerta y ":""}miedo técnico para empujarte a llamar.`,
      32,{family:"popup_scareware",isThreat:true,isManipulation:true,
        why:"Las alertas de virus reales nunca incluyen un número de teléfono ni bloquean el navegador.",
        advice:"Cierra la ventana. No llames al número. El soporte real no aparece así."})];
  return [];
}

// ─── NUEVOS DETECTORES V3.1 ────────────────────────────────────────────────

function detectBase64(rawText) {
  const alerts = [];
  // Patrón: ≥40 chars de base64 (excluyendo URLs que ya son base64 válido)
  const b64re = /\b([A-Za-z0-9+/]{40,}={0,2})\b/g;
  for (const m of rawText.matchAll(b64re)) {
    try {
      const decoded = Buffer.from(m[1], "base64").toString("utf8");
      // Solo procesar si el resultado parece texto real (no binario)
      if (!/[\x00-\x08\x0e-\x1f]/.test(decoded) && decoded.length > 10) {
        const normDecoded = normalizeText(decoded);
        // ¿El texto decodificado contiene URLs o palabras de riesgo?
        if (/https?:\/\/|hxxp/.test(decoded))
          alerts.push(makeAlert("Evasión","URL en base64",
            `Texto base64 oculta una URL: ${decoded.slice(0,60)}`,
            32,{family:"base64_url",isThreat:true,
              why:"Codificar URLs en base64 es una técnica para evadir filtros automáticos.",
              advice:"No copies ni abras URLs que encuentres así codificadas."}));
        else if (["urgente","verify","login","password","credencial","bloqueo"].some(t=>normDecoded.includes(t)))
          alerts.push(makeAlert("Evasión","Texto sensible en base64",
            `Contenido codificado contiene términos de riesgo.`,
            18,{family:"base64_evasion",isThreat:true,
              why:"Ocultar texto de phishing en base64 es evasión de filtros."}));
      }
    } catch { /* no es base64 válido */ }
  }
  return alerts;
}

function detectLegitContext(rawText, normText) {
  const signals = [];

  // 3A. NEWSLETTER / REPORTAJE — habla de amenazas sin ejecutarlas
  const reportageMarkers = [
    "investigadores advierten","según reportes","se ha detectado","estudio revela",
    "nueva campaña de","researchers warn","security researchers","new phishing campaign",
    "users are warned","experts say","according to","gestiona tus preferencias",
    "unsubscribe","date de baja","manage preferences","published by","mailing list",
    "view in browser","ver en el navegador",
    // Añadidos: boletines de ciberseg
    "esta semana en","esta semana en seguridad","boletín de seguridad","boletin de seguridad",
    "se recomienda no","security newsletter","weekly digest","roundup de seguridad",
    "se detectó una nueva","se detecto una nueva","advierten sobre",
    "campaña de phishing","campaña de estafa","campaña maliciosa",
  ];
  const reportageCount = reportageMarkers.filter(m => normText.includes(normalizeText(m))).length;
  if (reportageCount >= 2)
    signals.push({ id:"legit_reportage", score: -20,
      why:"El texto describe amenazas de forma periodística o educativa, no las ejecuta." });

  // 3B. OTP / CÓDIGO LEGÍTIMO — avisa expresamente que no lo compartas
  const otpLegitMarkers = [
    "no lo compartas","no lo comparta","do not share","if you did not request",
    "si no solicitaste","si usted no solicito","ignora este mensaje","ignore this message",
    "no pediremos tu clave","never ask for your password",
  ];
  const otpLegitCount = otpLegitMarkers.filter(m => normText.includes(normalizeText(m))).length;
  if (otpLegitCount >= 1)
    signals.push({ id:"legit_otp", score: -16,
      why:"El mensaje advierte que no se comparta el código, patrón de OTP legítimo." });

  // 3C. REFERENCIA A DOMINIO OFICIAL REAL — contiene dominio legítimo conocido
  const officialDomains = [
    "google.com","apple.com","microsoft.com","amazon.com","bancoestado.cl",
    "falabella.com","entel.cl","github.com","linkedin.com","accounts.google.com",
  ];
  const bodyUrls = extractUrls(rawText);
  const hasOfficialUrl = bodyUrls.some(u => {
    const dom = domainFromUrl(u);
    return officialDomains.some(od => dom===od || dom.endsWith("."+od));
  });
  if (hasOfficialUrl)
    signals.push({ id:"legit_official_domain", score: -10,
      why:"El enlace apunta a un dominio oficial conocido." });

  // 3D. COMUNICACIÓN INTERNA CORPORATIVA SIN URGENCIA REAL
  const corpMarkers = ["equipo de it","it team","recordatorio de política","security policy",
    "policy reminder","90 días","cada 90","regular password","política de contraseñas"];
  const corpCount = corpMarkers.filter(m => normText.includes(normalizeText(m))).length;
  if (corpCount >= 1)
    signals.push({ id:"legit_corp_policy", score: -8,
      why:"El mensaje parece comunicación interna de política corporativa." });

  // 3E. NOTIFICACIÓN OFICIAL REAL — informa sin pedir acción urgente ni enlace externo
  const officialNotifMarkers = [
    "fue procesada","ha sido procesada","puede revisar en","puede revisarlo en",
    "fue procesado","ha sido procesado","ya está disponible","ya está disponible",
    "no es necesario","no debes realizar","no requiere acción",
    "www.sii.cl","sii.cl","bancoestado.cl","falabella.com","entel.cl",
    "declaración fue procesada","declaracion fue procesada",
  ];
  const rawLow = rawText.toLowerCase();
  const hasOfficialDomain = ['www.sii.cl','sii.cl','bancoestado.cl','transbank.cl',
    'latam.com','amazon.com','mercadolibre.cl','amazon.com/orders',
    'accounts.google.com','github.com'].some(d => rawLow.includes(d));
  const officialNotifCount = officialNotifMarkers.filter(m =>
    normText.includes(normalizeText(m)) || rawText.toLowerCase().includes(m.toLowerCase())
  ).length;
  if (officialNotifCount >= 1 || hasOfficialDomain) {
    const notifDiscount = hasOfficialDomain ? -32 : -22;
    signals.push({ id:"legit_official_notif", score: notifDiscount,
      why:"El mensaje parece una notificación informativa de una institución oficial, sin pedir acción urgente." });
  }

  // 3F. ALERTA DE SEGURIDAD PROTECTORA (FIX NUEVO)
  // "Nuevo inicio de sesión", "alerta de seguridad", "si no fuiste tú" son
  // patrones de notificaciones legítimas de Google, Microsoft, bancos, etc.
  // NO son phishing aunque tengan credential+authority+URL.
  const securityNoticeCount = SECURITY_NOTICE_PHRASES.filter(p =>
    normText.includes(normalizeText(p))
  ).length;
  if (securityNoticeCount >= 1) {
    signals.push({ id:"legit_security_notice", score: -28,
      why:"El mensaje incluye una advertencia protectora ('si no fuiste tú'), patrón de notificación de seguridad legítima." });
  }

  // 3G. CONTEXTO COMERCIAL / MARKETING LEGÍTIMO (FIX NUEVO)
  // Correos de tiendas con ofertas, descuentos, "últimas unidades" son normales.
  // La urgencia comercial no equivale a urgencia fraudulenta.
  const commercialUrgencyCount = TERMS.commercial_urgency.filter(t =>
    normText.includes(normalizeText(t))
  ).length;
  // Solo aplicar si hay señales de newsletter o comercial (unsubscribe, etc.)
  const hasNewsletterContext = reportageMarkers.some(m => normText.includes(normalizeText(m)));
  const hasCommercialPattern = [
    "ver en el navegador","view in browser","unsubscribe","cancelar suscripción",
    "descuento","oferta","promo","sale","tienda","shop","store",
  ].some(t => normText.includes(normalizeText(t)));
  if (commercialUrgencyCount >= 1 && hasCommercialPattern) {
    signals.push({ id:"legit_commercial_urgency", score: -12,
      why:"La urgencia parece ser comercial (oferta/descuento), no fraudulenta." });
  }

  return signals;
}

function detectIndirectAction(normText) {
  const alerts = [];

  // Patrón: proceso/solicitud/trámite + pendiente/incompleto + hoy/cierre/plazo
  const hasProcess  = ["proceso","solicitud","tramite","operacion","gestion","expediente","caso"].some(t=>normText.includes(t));
  const hasPending  = ["pendiente","incompleto","sin confirmar","requiere confirmacion","requiere atencion","debe completar"].some(t=>normText.includes(t));
  const hasDeadline = ["antes del cierre","cierre de operaciones","antes de las","hoy mismo","este dia","vencimiento"].some(t=>normText.includes(t));
  const hasPortal   = ["portal","acceda","ingrese","acceder","completar el proceso","adjunto"].some(t=>normText.includes(t));

  // Scam de marketplace: "te pago yo", "paga primero el flete"
  const hasMarketRuse = ["paga primero","paga el flete","yo pago el flete","te mando el dinero primero","te transfiero primero","yo adelanto"].some(t=>normText.includes(t));
  if (hasMarketRuse)
    alerts.push(makeAlert("Marketplace","Trampa de pago adelantado",
      "Pide que pagues o anticipes algo antes de la transacción.",
      30,{family:"marketplace_advance_scam",isThreat:true,isManipulation:true,
        why:"En compraventas, quien pide que pagues primero el flete o la diferencia generalmente no enviará nada.",
        advice:"Usa solo los medios de pago de la plataforma oficial. Nunca hagas pagos externos."}));
  // Phishing que se disculpa: "entendemos que puede parecer sospechoso" → señal fuerte
  const hasDefensePhishing = ["puede parecer sospechoso","puede verse sospechoso","no es phishing","100% legitimo","100% legítimo","nunca te pediremos tu contraseña completa"].some(t=>normText.includes(t));
  if (hasDefensePhishing)
    alerts.push(makeAlert("Manipulación","Phishing que anticipa sospechas",
      "El mensaje se adelanta a defenderse contra sospecha, técnica de ingeniería social.",
      24,{family:"preemptive_defense_scam",isThreat:true,isManipulation:true,
        why:"Los mensajes legítimos no necesitan asegurarte que son legítimos. Este patrón es señal de ingeniería social.",
        advice:"Si el mensaje necesita convencerte de que no es fraude, desconfía más, no menos."}));
  if (hasProcess && hasPending && (hasDeadline || hasPortal))
    alerts.push(makeAlert("Acción","Lenguaje de acción indirecto",
      "Usa proceso/solicitud pendiente + plazo/portal sin mencionar palabras directas.",
      22,{family:"indirect_action",isThreat:true,isManipulation:true,
        why:"El atacante evita palabras de riesgo directas pero el patrón semántico es idéntico al phishing.",
        advice:"Verifica la solicitud contactando directamente a la entidad."}));

  // Patrón: número de referencia inventado + acción requerida
  if (/(?:solicitud|caso|expediente|ticket|folio|referencia)\s*(?:#|n[°º]?\.?)?\s*\d{4,}/i.test(normText) && hasPending)
    alerts.push(makeAlert("Acción","Número de referencia + pendiente",
      "Usa un número de caso/solicitud para dar legitimidad a una acción requerida.",
      16,{family:"fake_reference_number",isManipulation:true,
        why:"Los atacantes inventan números de referencia para que el mensaje parezca oficial."}));

  return alerts;
}


// ─── DETECTOR ESTRUCTURAL ────────────────────────────────────────────────────
// Detecta patrones de intención sin depender de keywords.
// Cubre los 3 bypasses más difíciles del motor.

function detectStructural(rawText, normText, urls) {
  const alerts = [];

  // ── PATRÓN 1: Rol de autoridad + solicitud directa de datos sensibles ────
  // "Soy de RRHH / área de / somos del banco + dame tu RUT/cuenta/clave"
  // No hay URL. Es vishing por escrito. El motor no lo ve porque no hay infraestructura.
  const hasAuthorityRole = /(?:soy (?:de |del |la )|área de |area de |hablo de parte de |le (?:escribo|contacto) desde |del (?:área|area|departamento)|somos del)/i.test(rawText);
  const hasSensitiveDataReq = /(?:rut|número de cuenta|numero de cuenta|datos de cuenta|datos bancarios|clave|pin|contraseña|número de tarjeta|numero de tarjeta|token|código de acceso)/i.test(rawText);
  const hasAskVerb = /(?:necesito que (?:me )?(?:conf|env|proporciones|indiques|facilites|compartas)|¿me (?:puedes|podrías) (?:dec|env|conf|prop)|puedes (?:dec|env|conf)|dime (?:tu|el|la)|cuéntame (?:tu|el)|cuentame (?:tu|el))/i.test(rawText);
  if (hasAuthorityRole && hasSensitiveDataReq && hasAskVerb)
    alerts.push(makeAlert("Estructura","Solicitud directa de datos sensibles",
      "Alguien que dice ser de una institución pide datos bancarios, RUT o credenciales directamente por mensaje.",
      42, { family:"direct_data_harvest", isThreat:true, isManipulation:true,
        why:"Las instituciones reales nunca piden datos sensibles por mensaje. Este patrón es vishing por escrito.",
        advice:"Llama tú al número oficial de la institución para verificar antes de dar cualquier dato." }));

  // ── PATRÓN 2: Disponibilidad + opacidad deliberada ────────────────────────
  // "¿Puedes atenderme?" + "no puedo explicar por escrito" + plazo
  // Primer paso del BEC en dos etapas. Sin keywords de transferencia todavía.
  const hasAvailRequest = /(?:¿puedes (?:reservar|confirmar|atender|estar disponible)|¿tienes (?:un momento|tiempo|el rato)|¿estás (?:disponible|libre|por ahí)|necesito que estés disponible)/i.test(rawText);
  const hasDelibDefer = /(?:no (?:puedo |quiero )?(?:detallar|explicar|decir|escribir) (?:por (?:aquí|escrito|acá|este medio)|ahora)|prefiero no (?:detallar|explicar|escribir)|es algo delicado|no es para (?:escribir|el chat|el correo)|cuanto antes|lo antes posible|no puede esperar)/i.test(rawText);
  const hasTimeConstraint = /(?:antes de las |hoy mismo|esta tarde|en el día|antes de (?:mañana|las \d)|no puede esperar|urgente pero)/i.test(rawText);
  if (hasAvailRequest && hasDelibDefer)
    alerts.push(makeAlert("Estructura","Disponibilidad + opacidad deliberada",
      "Pide disponibilidad urgente pero evita dar detalles por escrito. Primer paso de fraude en dos etapas.",
      38, { family:"two_stage_bec", isThreat:true, isManipulation:true,
        why:"El atacante primero confirma que la víctima responde antes de revelar la instrucción real (transferencia, datos, etc.).",
        advice:"Antes de confirmar disponibilidad, pregunta de qué se trata por un canal de voz conocido." }));

  // ── PATRÓN 3: Dominio corto desconocido + verbo de acción + sesión/cuenta ─
  // "Tu sesión expira. Renueva: http://bnc.cl/r9x"
  // URL con dominio real-pero-desconocido de ≤8 chars, sin TLD sospechoso,
  // acompañado de acción mínima. Los acortadores conocidos ya están cubiertos.
  const KNOWN_SHORT = new Set(['bit.ly','t.co','is.gd','s.id','ow.ly','buff.ly','cutt.ly','goo.gl','tinyurl.com']);
  const suspShortUrl = urls.find(u => {
    const d = domainFromUrl(u);
    if (!d || KNOWN_SHORT.has(d)) return false;
    // Dominio con ≤8 chars en la parte registrada y path con ≥4 chars de ruta aleatoria
    const root = regDomain(d).split('.')[0];
    const hasShortPath = /\/[a-z0-9]{3,8}$/i.test(u);
    return root.length <= 6 && hasShortPath;
  });
  if (suspShortUrl) {
    const d = domainFromUrl(suspShortUrl);
    const hasActionVerb = /(?:renueva|verifica|confirma|actualiza|ingresa|accede|entra|activa|valida)/i.test(rawText);
    const hasSessionCtx = /(?:sesión|sesion|cuenta|acceso|contraseña|clave|token|vence|expira)/i.test(rawText);
    // Fix: requerir AMBAS condiciones (acción + contexto de sesión/cuenta) para reducir FP
    // en correos de e-commerce con links cortos a sus propios subdominios.
    // senderDomains no está disponible en este contexto — usar solo isKnownEsp del link
    const linkIsKnownEsp = isKnownEsp(d);
    if (!linkIsKnownEsp && hasActionVerb && hasSessionCtx)
      alerts.push(makeAlert("URL","Dominio corto desconocido + acción de cuenta",
        `${d} es un dominio muy corto no reconocido como acortador legítimo, con ruta de aspecto aleatorio.`,
        32, { key:`structural:short:${d}`, family:"unknown_short_domain", isThreat:true,
          why:"Los dominios cortos no reconocidos con rutas aleatorias imitan acortadores legítimos para ocultar el destino.",
          advice:"No hagas clic. Busca el servicio mencionado directamente en su app o sitio oficial." }));
  }

  return alerts;
}

function analyze(text, _requestedMode = "auto") {
  const input    = text.slice(0, 25000);
  const normBody = normalizeText(stripUrls(input));
  const normFull = normalizeText(input);

  const urls          = extractUrls(input);
  const senderDomains = extractEmailDomains(input);
  const relayDomains  = extractRelayDomains(input);
  const entities      = extractEntities(input);
  const allDomains    = [...new Set([...urls.map(domainFromUrl).filter(Boolean),...senderDomains,...relayDomains])];

  // GLOBAL DETECTORS
  const raw = [
    ...detectSignals(normBody),
    ...detectUrls(urls, normBody, senderDomains),
    ...detectDomains(senderDomains, "Remitente"),
    ...detectDomains(relayDomains, "Relay"),
    ...detectPlaceholders(input),
    ...detectObfuscation(input),
    ...detectBase64(input),           // NUEVO: base64
    ...detectBec(normFull),
    ...detectOtp(normFull),
    ...detectSocialEngineering(normFull),
    ...detectFakeJob(normFull, input),
    ...detectMarketplace(normFull),
    ...detectPhoneInText(input),
    ...detectIndirectAction(normFull),
    ...detectBankChangeScam(normFull),
    ...detectInvestmentScam(normFull),
    ...detectMoneyMule(normFull),
    ...detectNumberChangeScam(normFull),
    ...detectPopupScareware(normFull, input),
    ...detectStructural(input, normFull, urls),
  ];

  // Brand mismatch remitente
  // Fix: excluir retailers legítimos que mencionan marcas de terceros en su catálogo.
  // Un retailer que vende Apple/Samsung/LG no está suplantando a esas marcas.
  const senderIsRetailer = [...senderDomains,...relayDomains].some(d =>
    [...KNOWN_RETAILER_SENDERS].some(rd => d === rd || d.endsWith("." + rd) || rd.includes(d))
  );
  // Fix: brand_content_spoof solo activa cuando:
  // (a) El remitente NO es un retailer conocido (evita "pcfactory menciona apple")
  // (b) El sender domain NO es un subdominio oficial de la marca mencionada
  // (c) El sender domain NO es una plataforma conocida que legítimamente menciona otras marcas
  // (d) La marca mencionada NO es una red social en contexto de footer
  //     (newsletters con "Síguenos en LinkedIn Instagram" → footer legítimo, no spoof)
  const senderIsPlatform = [...senderDomains,...relayDomains].some(d =>
    Object.values(BRAND_DOMAINS).some(official =>
      isOfficialDomain(d, official)  // el sender ya es una entidad de marca conocida
    )
  );

  // Detectar contexto de footer social: ¿aparecen varias redes juntas?
  // Si hay ≥2 marcas de redes sociales en el cuerpo + contexto de seguir/suscripción,
  // es un footer estándar de newsletter, no una suplantación.
  const socialBrandsInBody = [...SOCIAL_FOOTER_BRANDS].filter(b => normBody.includes(b));
  const hasSocialFooterContext = socialBrandsInBody.length >= 2 ||
    (socialBrandsInBody.length >= 1 &&
     SOCIAL_FOOTER_CONTEXT.some(ctx => normBody.includes(normalizeText(ctx))));

  if (!senderIsRetailer && !senderIsPlatform) {
    for (const [brand, official] of Object.entries(BRAND_DOMAINS)) {
      if (!normBody.includes(brand)) continue;
      // No activar para marcas de redes sociales en footer de newsletter
      if (SOCIAL_FOOTER_BRANDS.has(brand) && hasSocialFooterContext) continue;
      for (const dom of [...senderDomains,...relayDomains]) {
        if (isOfficialDomain(dom, official)) break;  // sender es subdominio oficial → OK
        raw.push(makeAlert("Remitente","Marca ≠ dominio remitente",
          `Usa '${brand}' pero el remitente es ${dom}.`,28,
          {key:`brand_sender:${brand}:${dom}`,family:"brand_content_spoof",isThreat:true,
           why:`El mensaje usa el nombre de ${brand} para parecer oficial, pero el remitente real es otro.`}));
        break;
      }
    }
  }

  // Entity vs infraestructura
  if (entities.length && allDomains.length) {
    const suspDoms  = allDomains.filter(d=>domainFlags(d).length||isAbused(d));
    const unrelDoms = [...senderDomains,...relayDomains].filter(d=>!entities.some(e=>entityMatchesDomain(e,d)));
    const hasRiskyCtx = [...TERMS.delivery,...TERMS.risky_action,...TERMS.money].some(t=>normBody.includes(normalizeText(t)));
    const target = suspDoms[0]||unrelDoms[0];
    if (hasRiskyCtx && target) {
      const entity = entities.find(e=>!entityMatchesDomain(e,target))||entities[0];
      raw.push(makeAlert("Entidad","Entidad ≠ infraestructura",
        `'${entity}' vs ${target}`,22,
        {key:`entity:${entity}:${target}`,family:"entity_infra_mismatch",isThreat:true,
         why:`El mensaje aparenta ser de '${entity}' pero usa infraestructura diferente (${target}).`}));
    }
  }

  // CORRELACIONES
  const normForLegit = normalizeText(input);
  const prelimLegit = detectLegitContext(input, normForLegit);
  const isReportageCtx = prelimLegit.some(l=>l.id==="legit_reportage");
  const correlations = detectCorrelations(raw, isReportageCtx);
  const allRaw       = [...raw, ...correlations];

  // CONTEXT ENRICHER
  const context = enrichContext(input);
  const bonus   = contextBonus(context);

  // CONTEXTO LEGÍTIMO — señales que reducen el score (NUEVO)
  const legitSignals = detectLegitContext(input, normFull);

  // DEDUPE + CAP
  const alerts = dedupeAlerts(allRaw);

  // SCORE
  const {raw: rawScore, threat, manip} = scoreAlerts(alerts);
  // Aplicar descuentos de contexto legítimo (más agresivo si hay señales de reportaje)
  const reportageCount = legitSignals.filter(l=>l.id==="legit_reportage").length;
  const maxDiscount = reportageCount > 0 ? 60 : 45;
  const legitDiscount = Math.min(maxDiscount, legitSignals.reduce((s,l)=>s+Math.abs(l.score),0));
  const score     = Math.max(0, Math.min(100, rawScore + bonus - legitDiscount));
  const composite = Math.max(score, threat - Math.round(legitDiscount*0.65), manip - Math.round(legitDiscount*0.4));
  const hasTrust  = alerts.some(a=>a.isTrust);
  const trustScore= alerts.filter(a=>a.isTrust).reduce((s,a)=>s+a.severity,0);
  const risk      = riskLevel(composite, hasTrust, trustScore);
  const confidence= alerts.filter(a=>a.severity>=20).length>=2 ? "alta"
                  : alerts.filter(a=>a.severity>=20).length>=1 ? "media" : "baja";

  // Añadir señales legítimas como alertas de trust para la UI
  for (const ls of legitSignals)
    alerts.push(makeAlert("Contexto legítimo", ls.id, ls.why, ls.score, {isTrust:true, family:ls.id}));

  const rawPattern = classifyPattern(alerts);
  // Si solo hay señales débiles Y score < 25, el pattern no debe ser acusatorio
  // para no mostrar etiquetas alarmistas en mensajes Bajo.
  const onlyWeakAlerts = alerts.filter(a=>a.severity>0&&!a.isTrust).every(a=>a.isWeak);
  const pattern = (onlyWeakAlerts && score < 25)
    ? { label: "Sin señales de fraude", desc: "No detectamos patrones de riesgo en este mensaje." }
    : rawPattern;
  const top3    = alerts.filter(a=>a.severity>0&&!a.isTrust).slice(0,3).map(a=>a.title.toLowerCase()).join(", ");

  // Enriquecer alertas con display_text: lo que ve el usuario
  // Prioridad: why (explicación de usuario) > detail limpio > title
  const INTERNAL_PREFIXES = ["Encontrado:","Coincidencias:","Combinación detectada:","Combinación:","Señal de tipo"];
  const enrichedAlerts = alerts.map(a => {
    let display = a.why || "";
    if (!display || INTERNAL_PREFIXES.some(p => display.startsWith(p))) {
      // Intentar limpiar el detail si tiene datos técnicos
      const d = a.detail || "";
      display = INTERNAL_PREFIXES.some(p => d.startsWith(p)) ? "" : d;
    }
    if (!display) display = `Señal: ${a.title}`;
    return { ...a, display_text: display };
  });

  return {
    mode:               context.id,
    context,
    risk, score,
    threat_score:       threat,
    manipulation_score: manip,
    legit_discount:     legitDiscount,
    confidence_level:   confidence,
    families_detected:  [...new Set(enrichedAlerts.map(a=>a.category))].sort(),
    primary_family:     enrichedAlerts.find(a=>a.family&&a.severity>0)?.family || "",
    critical_signals:   enrichedAlerts.filter(a=>a.severity>=20).map(a=>a.title).slice(0,8),
    triggered_rules:    enrichedAlerts.map(a=>a.title),
    pattern,
    explanation: top3
      ? `Riesgo ${risk} · ${score}/100. ${pattern.label}. Señales: ${top3}.`
      : `Riesgo ${risk}. Sin señales fuertes. Verifica contexto y remitente.`,
    alerts: enrichedAlerts,
    urls,
    recommendations: buildRecommendations(risk, enrichedAlerts, urls, context),
  };
}

// ─── BACKWARD COMPAT: inferMode ya no controla el análisis ───────────────────
// Se mantiene solo por si UI.js lo llama — devuelve el contexto enriquecido
function inferMode(text) { return enrichContext(text).id; }


// SECCIÓN 3: UI + INTEGRACIÓN HÍBRIDA v3
// ═══════════════════════════════════════
// Gestiona: historia, toast, botones, llamada async al servidor ML,
// fusión híbrida JS+ML, y publicación del resultado en window._hybridResult
// para que el script inline de index.html lo consuma.

// ─── SEGURIDAD: ESCAPE HTML ──────────────────────────────────────────────────
function esc(value) {
  return String(value).replace(/[&<>"']/g, ch =>
    ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;" })[ch]
  );
}

// ─── HISTORIA ─────────────────────────────────────────────────────────────────
const HISTORY_KEY = "phishsense_v2_history";
const RISK_VALUES = new Set(["Bajo","Medio","Alto","Crítico"]);

function loadHistory() {
  try {
    const raw = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    if (!Array.isArray(raw)) return [];
    return raw.filter(item =>
      typeof item.mode    === "string" &&
      typeof item.risk    === "string" && RISK_VALUES.has(item.risk) &&
      typeof item.score   === "number" && item.score >= 0 && item.score <= 100 &&
      typeof item.preview === "string"
    );
  } catch { return []; }
}

function saveHistory(text, result) {
  const items = loadHistory();
  items.unshift({
    mode:    String(result.pattern?.label || result.mode || "").slice(0, 60),
    risk:    RISK_VALUES.has(result.risk) ? result.risk : "Bajo",
    score:   Math.max(0, Math.min(100, Math.round(result.score || 0))),
    preview: text.replace(/\s+/g," ").trim().slice(0, 110),
    createdAt: new Date().toISOString(),
  });
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, 8))); }
  catch { /* storage full */ }
}

// ─── TOAST ────────────────────────────────────────────────────────────────────
let _toastTimer = null;
function showToast(msg) {
  const t = document.getElementById("toast");
  if (!t) return;
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove("show"), 2400);
}

// ─── NO-OPS SEGUROS ───────────────────────────────────────────────────────────
function navigate() {}
function setTerminal(msg) {
  const el = document.getElementById("terminalLoader");
  if (el && msg) el.textContent = msg;
}
function syncInputState() {
  const input   = document.getElementById("emailInput");
  const counter = document.getElementById("charCounter");
  if (!input || !counter) return;
  const count = input.value.length;
  counter.textContent = `${count.toLocaleString("es-CL")} caracter${count===1?"":"es"}`;
}
function animateProgress(onDone) {
  const bar = document.getElementById("progressBar");
  let value = 0;
  const msgs = [
    "Escaneando patrones de amenaza",
    "Analizando infraestructura",
    "Correlacionando señales",
    "Calibrando con modelo semántico",
  ];
  let mi = 0;
  setTerminal(msgs[0]);
  const t = setInterval(() => {
    value += 5;
    const ni = Math.min(msgs.length - 1, Math.floor(value / 27));
    if (ni !== mi) { mi = ni; setTerminal(msgs[mi]); }
    if (bar) bar.style.width = `${Math.min(value, 90)}%`;  // Dejar 90% hasta que ML responda
    if (value >= 90) clearInterval(t);
  }, 20);
  return t;
}
function finishProgress() {
  const bar = document.getElementById("progressBar");
  if (bar) bar.style.width = "100%";
  setTerminal("Análisis completado");
}
function renderHistory() {
  const list = document.getElementById("historyList");
  if (!list) return;
  const items = loadHistory();
  list.innerHTML = items.length
    ? items.slice(0, 5).map(i =>
        `<li><strong>${esc(i.risk)} · ${i.score}/100</strong>${esc(i.preview.slice(0, 80))}…</li>`
      ).join("")
    : "<li>Sin análisis recientes.</li>";
}

// ─── LLAMADA AL SERVIDOR ML ───────────────────────────────────────────────────
const ML_SERVER_URL  = "http://127.0.0.1:8765/predict";
const ML_TIMEOUT_MS  = 900;   // ms máximos de espera — si tarda más, continuar sin ML
let   _mlAvailCache  = null;  // null=desconocido, true=disponible, false=no disponible
let   _mlLastCheck   = 0;
const ML_RECHECK_MS  = 30000; // re-verificar disponibilidad cada 30s

async function callML(text) {
  // Si ya sabemos que no está disponible y el recheck no ha vencido, retornar null
  const now = Date.now();
  if (_mlAvailCache === false && (now - _mlLastCheck) < ML_RECHECK_MS) {
    return null;
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ML_TIMEOUT_MS);

    const response = await fetch(ML_SERVER_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ text }),
      signal:  controller.signal,
    });
    clearTimeout(timer);

    if (!response.ok) {
      _mlAvailCache = false;
      _mlLastCheck  = now;
      return null;
    }

    const data = await response.json();
    _mlAvailCache = true;
    _mlLastCheck  = now;
    return data;

  } catch {
    // Timeout, network error, servidor no disponible
    _mlAvailCache = false;
    _mlLastCheck  = now;
    return null;
  }
}

// ─── CONSTRUIR RESULTADO COMPATIBLE CON LA UI EXISTENTE ───────────────────────
// El script inline de index.html espera el mismo contrato que analyze() devuelve:
// { risk, score, alerts, pattern, recommendations, urls, ... }
// Además publicamos el resultado híbrido completo en window._hybridResult.

function buildUiResult(jsResult, hybridResult) {
  // Mapear risk_level híbrido a los valores que espera la UI
  const RISK_MAP = {
    "Bajo":    "Bajo",
    "Medio":   "Medio",
    "Alto":    "Alto",
    "Crítico": "Crítico",
  };
  const risk  = RISK_MAP[hybridResult.risk_level] || jsResult.risk;
  const score = hybridResult.final_score;

  // Enriquecer el pattern con información del ML si aplica
  let pattern = hybridResult.pattern || jsResult.pattern;
  if (hybridResult.threat_category_label && score >= 25) {
    pattern = {
      ...pattern,
      label: hybridResult.threat_category_label || pattern.label,
      desc:  hybridResult.summary || pattern.desc || "",
    };
  } else if (hybridResult.hint_id === "otp_legit_aviso") {
    pattern = {
      label: "Código de verificación legítimo",
      desc:  hybridResult.summary,
    };
  } else if (hybridResult.hint_id === "newsletter_confirmed") {
    pattern = {
      label: "Newsletter legítimo",
      desc:  hybridResult.summary,
    };
  } else if (hybridResult.review_needed) {
    pattern = {
      ...pattern,
      desc: hybridResult.summary || "Verifica por un canal oficial antes de actuar.",
    };
  }

  // Agregar alerta de review_needed si aplica (visible en la UI como señal)
  const alerts = [...(jsResult.alerts || [])];
  if (hybridResult.review_needed && !hybridResult.debug?.ml_available) {
    // Sin ML: no agregar nada extra
  } else if (hybridResult.review_needed) {
    alerts.push({
      title:        "Señales mixtas",
      why:          hybridResult.summary || "El análisis detectó señales contradictorias.",
      display_text: hybridResult.summary || "Verifica por un canal oficial.",
      severity:     0,
      isTrust:      false,
      family:       "hybrid_review",
      category:     "Análisis híbrido",
    });
  }

  return {
    // Campos que espera el index.html (compatibilidad)
    risk,
    score,
    alerts,
    urls:            jsResult.urls || [],
    pattern,
    recommendations: hybridResult.recommendations || jsResult.recommendations || [],
    confidence_level: jsResult.confidence_level || "baja",
    families_detected: jsResult.families_detected || [],
    primary_family:   jsResult.primary_family || "",
    critical_signals: jsResult.critical_signals || [],
    // Extra: resultado híbrido completo para la UI avanzada
    _hybrid: hybridResult,
  };
}

// ─── FLUJO PRINCIPAL DE ANÁLISIS ─────────────────────────────────────────────
let _sampleIndex = 0;

document.addEventListener("DOMContentLoaded", () => {
  const input      = document.getElementById("emailInput");
  const analyzeBtn = document.getElementById("analyzeButton");
  const clearBtn   = document.getElementById("clearButton");
  const sampleBtn  = document.getElementById("sampleButton");
  const riskLabel  = document.getElementById("riskLabel");

  // charCounter
  input?.addEventListener("input", syncInputState);
  syncInputState();

  // Ejemplo
  sampleBtn?.addEventListener("click", () => {
    if (!input) return;
    input.value = PRACTICE_EXAMPLES[_sampleIndex % PRACTICE_EXAMPLES.length];
    _sampleIndex++;
    syncInputState();
    input.focus();
    showToast("Ejemplo cargado");
  });

  // Limpiar
  clearBtn?.addEventListener("click", () => {
    if (!input) return;
    input.value = "";
    syncInputState();
    window._hybridResult = null;
    if (typeof window._notphishReset === "function") window._notphishReset();
    else {
      document.getElementById("resultBlock")?.classList.remove("visible");
      document.getElementById("progressBlock")?.classList.remove("visible");
    }
  });

  // ── Analizar — flujo híbrido async ──────────────────────────────────────────
  analyzeBtn?.addEventListener("click", async () => {
    const text = input?.value?.trim() || "";
    if (!text) { showToast("// pega un mensaje primero"); return; }

    analyzeBtn.disabled = true;
    window._hybridResult = null;

    // Mostrar progreso
    document.getElementById("resultBlock")?.classList.remove("visible");
    document.getElementById("progressBlock")?.classList.add("visible");
    if (typeof window._notphishReset === "function") {
      // Solo resetear el bloque de resultados, mantener el input
    }
    const progressTimer = animateProgress(() => {});

    try {
      // 1. Motor JS (siempre — sincrónico)
      const jsResult = analyze(text, "auto");

      // 2. Servidor ML (async — con timeout)
      //    Corre en paralelo mientras el progress sigue
      const mlResult = await callML(text);

      // 3. Fusión híbrida
      let hybridResult;
      if (typeof combineHybridResult !== "undefined") {
        hybridResult = combineHybridResult(jsResult, mlResult, text);
      } else {
        // Fallback si hybrid.js no está cargado
        hybridResult = {
          risk_level:   jsResult.risk,
          final_score:  jsResult.score,
          action:       jsResult.score >= 75 ? "block_alert" : jsResult.score >= 50 ? "warn_strong" : jsResult.score >= 25 ? "warn" : "allow",
          hint_id:      "insufficient_evidence",
          summary:      jsResult.pattern?.desc || "",
          pattern:      jsResult.pattern,
          recommendations: jsResult.recommendations || [],
          signals:      [],
          trust_signals: [],
          evidence_fragments: [],
          review_needed: false,
          uncertain:    false,
          threat_category: null,
          threat_category_label: null,
          threat_confidence: jsResult.confidence_level || "baja",
          debug:        { ml_available: false, technical_score: jsResult.score },
        };
      }

      // 4. Construir resultado compatible con la UI
      const uiResult = buildUiResult(jsResult, hybridResult);

      // 5. Guardar para que index.html lo consuma
      window._hybridResult = hybridResult;

      // 6. Guardar historial
      saveHistory(text, uiResult);
      renderHistory();

      // 7. Terminar progreso y disparar render en index.html
      clearInterval(progressTimer);
      finishProgress();

      // Pequeña pausa para que el usuario vea 100%
      await new Promise(r => setTimeout(r, 80));

      // Publicar en DOM para que el MutationObserver de index.html lo detecte
      if (riskLabel) riskLabel.textContent = uiResult.risk;
      const sl = document.getElementById("scoreLabel");
      if (sl) sl.textContent = String(uiResult.score);

      // Guardar resultado completo para que el renderAll de index.html lo use
      window._lastAnalyzeResult = uiResult;

      // Indicar si ML estuvo disponible (para UI informativa)
      const mlBadge = document.getElementById("mlStatusBadge");
      if (mlBadge) {
        mlBadge.textContent = mlResult ? "ML activo" : "JS solo";
        mlBadge.title = mlResult
          ? `ML: ${hybridResult.debug?.ml_label} (${(hybridResult.debug?.ml_confidence * 100 || 0).toFixed(0)}%)`
          : "Servidor ML no disponible — análisis con motor JS";
      }

    } catch (e) {
      console.error("NotPhish hybrid error:", e);
      showToast("// error al analizar");
      clearInterval(progressTimer);
    } finally {
      analyzeBtn.disabled = false;
    }
  });

  // ── Reset público ────────────────────────────────────────────────────────────
  window._notphishReset = () => {
    document.getElementById("resultBlock")?.classList.remove("visible");
    document.getElementById("progressBlock")?.classList.remove("visible");
    document.getElementById("detailSection")?.classList.remove("open");
    const dt = document.getElementById("detailToggle");
    if (dt) dt.textContent = "ver log técnico ↓";
  };
});
