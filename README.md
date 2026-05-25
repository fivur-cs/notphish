# ¿Qué pasa cuando las reglas no son suficientes?

En el proyecto anterior, [Social Engineering Scanner](https://github.com/fabianubilla/social-engineering-scanner), trabajé con una idea simple:
detectar phishing buscando palabras sospechosas.

Ese enfoque sirve para aprender, pero tiene límites claros:
genera falsos positivos, puede ser evadido y no entiende bien el contexto.

NotPhish nace desde esa pregunta:

> ¿qué pasa si combinamos reglas simples con un modelo de machine learning?

---

# NotPhish

NotPhish es un proyecto educativo para explorar cómo puede evolucionar un detector de phishing cuando deja de depender solo de palabras clave.

Combina tres capas:

- reglas en JavaScript
- un modelo de ML (Machine Learning)
- una capa híbrida que decide cómo combinar ambas respuestas

La idea no es que el sistema sea perfecto.

La idea es entender qué mejora al agregar más capas…
y qué problemas nuevos aparecen.

---

## Qué vamos a aprender

- Cómo funciona un detector con múltiples capas
- Por qué las reglas simples no bastan siempre
- Qué hace un modelo de ML aplicado a texto
- Qué significa convertir texto en números usando TF-IDF
- Por qué combinar reglas y ML no es tan directo
- Qué limitaciones siguen apareciendo incluso con un sistema más avanzado

---

## Capturas

Algunas vistas de la interfaz en funcionamiento:

<p align="center">
  <img src="screenshots/inicio.png" width="200"/>
  <img src="screenshots/critico.png" width="200"/>
  <img src="screenshots/analizado.png" width="200"/>
  <img src="screenshots/limpio.png" width="200"/>
</p>

---

## La interfaz

La interfaz intenta explicar el resultado en lenguaje simple.

La idea no es solo decir:

```text
riesgo alto
```

o

```text
riesgo bajo
```

sino mostrar qué señales encontró el sistema y qué acción segura podría tomar la persona.

Está pensada para que el análisis sea más fácil de entender,
especialmente para usuarios que no necesariamente conocen conceptos técnicos de ciberseguridad.

---

# Cómo usarlo

```bash
git clone https://github.com/fabianubilla/notphish.git

cd notphish

pip install scikit-learn joblib flask

python server.py
```

Luego abre `index.html` en el navegador.

También puedes abrir `index.html` directamente sin Python,
pero en ese caso solo funcionará la capa de reglas en JavaScript.

---

# Cómo funciona por dentro

NotPhish combina tres capas.

Cada capa aporta algo distinto, pero también introduce nuevos problemas.

```text
reglas JS → modelo ML → sistema híbrido
```

---

## Capa 1 — Motor de reglas

La primera capa está en `app.js`.

Es parecida a la idea del scanner:
buscar señales sospechosas dentro del texto.

Pero en vez de sumar 1 punto por cada palabra,
este motor usa pesos distintos según la importancia de cada señal.

No todas las señales valen lo mismo.

Por ejemplo:

- una palabra urgente puede ser una señal débil
- un enlace extraño puede ser una señal más fuerte
- un dominio que imita a una marca conocida puede ser una señal crítica

---

### Qué detecta esta capa

- Dominios que imitan marcas conocidas  
  Ejemplo: `banco-santander-seguro.xyz`

- URLs acortadas  
  Ejemplo: `bit.ly`

- URLs ofuscadas  
  Ejemplo: `hxxps://`

- Pedidos de OTP  
  OTP (One-Time Password) significa código de un solo uso, como los códigos que llegan por SMS o app bancaria.

- Patrones de CEO Fraud  
  Fraude donde alguien se hace pasar por un jefe o autoridad para pedir una acción urgente.

- Señales de ingeniería social  
  Urgencia, autoridad, beneficio, bloqueo o presión.

---

### Por qué esta capa no basta

Las reglas pueden detectar señales visibles,
pero siguen teniendo el mismo problema de fondo:

no entienden completamente el contexto.

Un mensaje puede no tener enlaces raros ni palabras típicas,
y aun así ser manipulación.

O al revés:

un mensaje legítimo puede tener palabras como “urgente”, “cuenta” o “verificación”
y activar alertas innecesarias.

---

## Capa 2 — Modelo de Machine Learning

La segunda capa usa un modelo de ML (Machine Learning).

La idea es que el sistema no dependa solo de reglas escritas a mano,
sino que pueda aprender patrones a partir de ejemplos.

El modelo fue entrenado con textos clasificados como legítimos o sospechosos.

No “entiende” como una persona,
pero puede aprender que ciertas combinaciones de palabras aparecen con más frecuencia
en mensajes fraudulentos.

---

### Qué modelo usa

El modelo principal usa SGD (Stochastic Gradient Descent).

Dicho simple:

es un modelo lineal que aprende ajustando pesos internos.

No es una red neuronal.
No es un LLM.
No “razona” el mensaje.

Aprende patrones estadísticos desde los datos de entrenamiento.

---

### Qué es TF-IDF

Un modelo no puede trabajar directamente con texto como lo hacemos nosotros.

Primero necesita convertir ese texto en números.

Para eso se usa TF-IDF (Term Frequency–Inverse Document Frequency).

La idea básica es:

- si una palabra aparece mucho en un mensaje, puede ser importante
- pero si aparece en todos los mensajes, probablemente no dice mucho
- si una palabra o expresión aparece en ciertos mensajes sospechosos, puede tener más peso

Por ejemplo, palabras muy comunes como:

```text
el
de
que
para
```

aportan poco.

Pero expresiones como:

```text
verifica tu cuenta
expira hoy
código de seguridad
```

pueden aportar más información.

TF-IDF ayuda al modelo a transformar texto en números útiles para clasificar.

---

### Qué son los n-grams

El modelo también puede mirar grupos de palabras o caracteres.

Eso se llama n-grams.

Un n-gram es una secuencia de elementos.

Por ejemplo, en palabras:

```text
expira hoy
verifica cuenta
código seguridad
```

pueden decir más que cada palabra por separado.

También existen n-grams de caracteres.

Eso sirve para detectar pequeñas variaciones dentro de palabras,
como cuando alguien escribe algo de forma rara para evadir filtros.

Por ejemplo:

```text
urgente
urgentee
urg3nte
```

---

### Limitación importante

El modelo fue entrenado principalmente con datos en inglés.

Eso significa que su rendimiento en español puede ser más débil.

Esta parte es importante porque muchos sistemas parecen funcionar bien en general,
pero bajan su calidad cuando cambian el idioma, el contexto cultural
o el tipo de mensaje.

---

## Capa 3 — Sistema híbrido

La tercera capa está en `hybrid.js`.

Aquí aparece uno de los problemas más interesantes del proyecto:

¿qué pasa si las reglas dicen una cosa y el modelo dice otra?

Por ejemplo:

- las reglas pueden ver pocas señales
- el modelo puede encontrar patrones sospechosos
- o el modelo puede exagerar el riesgo en un mensaje legítimo

Entonces no basta con sumar todo y listo.

Hay que decidir cuánto peso darle a cada capa.

---

### Evidence gate

Para eso existe el evidence gate.

Evidence gate significa algo así como “compuerta de evidencia”.

Es una parte del sistema que decide cuánta influencia puede tener el modelo de ML
según las señales disponibles.

Por ejemplo:

- si el texto es muy corto, el ML puede quedar limitado
- si no hay señales claras, el ML no debería disparar una alerta fuerte por sí solo
- si las reglas encuentran señales importantes, el ML puede aportar más
- si hay señales de legitimidad, el sistema puede ser más cuidadoso

La idea es evitar que el modelo cambie demasiado el resultado
cuando no hay suficiente evidencia.

---

### Por qué esto importa

Combinar reglas y ML no es simplemente decir:

```text
reglas + modelo = mejor detector
```

A veces mejora.

Pero también puede traer problemas nuevos:

- más falsos positivos
- exceso de confianza en el modelo
- errores por idioma
- errores por mensajes demasiado cortos
- conflictos entre señales

Por eso el sistema híbrido intenta equilibrar ambas capas.

No lo hace perfecto.

Pero justamente ahí está el aprendizaje.

---

# Limitaciones conocidas

NotPhish sigue teniendo límites importantes.

Documentarlos es parte del objetivo del proyecto.

- Puede generar falsos positivos en mensajes legítimos con lenguaje agresivo o comercial.
- El rendimiento en español puede ser menor porque el modelo fue entrenado principalmente con datos en inglés.
- No analiza imágenes, capturas ni códigos QR.
- No analiza archivos adjuntos.
- No revisa headers reales del correo.
- No verifica en tiempo real si un dominio existe o si está activo.
- Puede ser evadido si alguien conoce bien las reglas.

Estas limitaciones no hacen que el proyecto pierda valor.

Al contrario:
ayudan a entender por qué la detección real de phishing necesita varias capas
y por qué ningún enfoque aislado resuelve todo.

---

# Qué no analiza todavía

NotPhish analiza principalmente el contenido del mensaje.

No analiza todavía los headers del correo,
que son los metadatos técnicos donde aparecen cosas como:

- servidores por los que pasó el mensaje
- dominio real de envío
- autenticación SPF / DKIM / DMARC
- firmas digitales
- rutas de entrega

SPF, DKIM y DMARC son mecanismos usados para verificar
si un correo realmente viene del dominio que dice representar.

Esa sería otra capa distinta de análisis,
más cercana al análisis técnico o forense del correo.

---

# Cómo leer el código si eres estudiante

Este orden puede ayudar a entender el proyecto sin perderse:

1. **`config.json`**  
   Contiene umbrales y parámetros.  
   Es un buen punto de entrada porque muestra qué valores afectan las decisiones del sistema.

2. **`app.js`**  
   Contiene el motor de reglas.  
   Es la parte más parecida al scanner, pero con más señales y pesos.

3. **`hybrid.js`**  
   Contiene la lógica para combinar reglas y ML.  
   Conviene mirar primero `computeEvidenceGate()` y después `computeFinalScore()`.

4. **`server.py`**  
   Carga el modelo y responde las solicitudes desde la interfaz.  
   Es el puente entre Python y la parte web.

5. **`index.html`**  
   Contiene la interfaz.  
   Muestra el análisis de forma visual y más fácil de leer.

---

# Estructura del proyecto

```text
notphish/
├── index.html       # Interfaz web
├── app.js           # Motor de reglas JS
├── hybrid.js        # Sistema híbrido: evidence gate y fusión JS + ML
├── hints.js         # Textos educativos por tipo de amenaza
├── server.py        # Servidor Flask para el modelo ML
├── config.json      # Umbrales y parámetros
└── models/
    ├── primary_model_candidate.joblib
    └── subcategory_model_candidate.joblib
```

---

# Proyecto anterior

## [¿Se puede detectar phishing solo buscando palabras sospechosas?](https://github.com/fabianubilla/social-engineering-scanner)

Ese proyecto es el punto de partida.

Muestra cómo funcionan las reglas simples,
por qué sirven para aprender y por qué no bastan para detectar phishing real.

NotPhish continúa desde ahí.

---

# Tecnologías

- HTML
- CSS
- JavaScript vanilla
- Python
- Flask
- scikit-learn
- joblib
- TF-IDF
- SGD

---

# Sobre este proyecto

Soy estudiante de ingeniería informática y ciberseguridad. A la fecha de este proyecto, mis conocimientos de programación están en una etapa inicial: fundamentos, lógica y exploración práctica.

Este proyecto fue construido usando Claude (Anthropic) como herramienta de desarrollo y aprendizaje. La IA tuvo un rol importante en la implementación, en decisiones técnicas y en la generación del código.

Mi rol fue definir qué quería explorar, probar el sistema, iterar ideas, evaluar propuestas, descartar lo que no tenía sentido y entender progresivamente cómo funcionaban las capas del detector.

Lo comparto como parte de un proceso real de aprendizaje, porque construir algo concreto me ayudó mucho más que solo leer teoría.

Espero que también pueda servirle a otros estudiantes que estén empezando y quieran entender cómo un detector puede evolucionar desde reglas simples hacia sistemas híbridos.

---

# Licencia

MIT
