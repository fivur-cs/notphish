# NotPhish

Proyecto de aprendizaje sobre detección de phishing.

---

## Cómo fue construido — y por qué importa decirlo

Soy estudiante de ingeniería informática y ciberseguridad. A la fecha de este proyecto,
mis conocimientos de programación son básicos: fundamentos, lógica y exploración.

Este proyecto fue construido usando Claude (Anthropic) como herramienta de desarrollo.
La IA tuvo un rol importante en la implementación, en muchas decisiones técnicas y en
la generación del código.

Mi rol fue definir qué quería explorar, iterar ideas, evaluar propuestas, descartar
lo que no tenía sentido y aprender progresivamente cómo funcionaba el sistema.

Lo publico como parte de un proceso real de aprendizaje. Creo que hoy aprender
también implica saber trabajar con herramientas de IA, pero entendiendo sus límites
y siendo transparente sobre cómo se usaron.

---

## Capturas

<p align="center">
  <img src="screenshots/inicio.png" width="200"/>
  <img src="screenshots/critico.png" width="200"/>
  <img src="screenshots/analizado.png" width="200"/>
  <img src="screenshots/limpio.png" width="200"/>
</p>

---

## Por qué existe

Empecé con una pregunta simple:

> **¿cómo sabe un programa que un mensaje es una estafa?**

Primero construí [`social-engineering-scanner`](https://github.com/fivur-cs/social-engineering-scanner)
— un script Bash que busca palabras clave con `grep`. Funciona para casos obvios,
pero tiene falsos positivos altos y se evade fácil.

NotPhish nació para explorar qué ocurre cuando intentas ir más allá de reglas fijas:
mezclar señales técnicas, contexto semántico y distintas capas de análisis.

---

## Para quién es la interfaz

Pensada para personas con baja alfabetización digital — especialmente adultos mayores.
Lenguaje simple, sin tecnicismos, enfocada en explicar qué encontró el análisis
y qué hacer después.

---

## Qué hace

- Analiza texto libre: correos, SMS, WhatsApp, cualquier mensaje
- Detecta señales técnicas y semánticas de manipulación
- Muestra un puntaje de 0 a 100 con explicación en lenguaje simple
- Recomienda qué hacer según el nivel de riesgo
- Todo el análisis ocurre localmente — ningún texto sale del equipo

---

## Cómo funciona por dentro

Esta parte resume la arquitectura general del proyecto y cómo se conectan sus piezas principales.

NotPhish tiene tres capas que trabajan juntas:

---

### Capa 1 — Motor de reglas JavaScript (`app.js`)

Es el corazón del sistema. Analiza el texto buscando señales técnicas
concretas, no solo palabras sueltas.

**Qué detecta:**

- **Dominios que imitan marcas conocidas** (`banco-estado-seguro.xyz`) —
  compara el dominio del enlace contra una lista de dominios oficiales
- **URLs acortadas** (`bit.ly`) — ocultan el destino real
- **URLs ofuscadas** (`hxxps://`) — técnica para que los filtros no detecten el enlace
- **Pedidos de OTP** — cuando alguien pide que compartas un código que llegó a tu celular
- **Patrones de BEC** (fraude del jefe) — urgencia + silencio + transferencia
- **Señales de ingeniería social** — urgencia artificial, suplantación de autoridad,
  promesas de beneficio, amenazas de bloqueo

**Cómo funciona el scoring:**

Cada señal tiene un peso numérico. El score final se capea a 100 —
si un texto activa señales por 270 puntos, el resultado igual es 100.
El log técnico muestra los pesos individuales para entender qué activó cada cosa,
no para que sumen el total.

**Señales débiles vs señales duras:**

Las señales débiles (urgencia genérica, mención de una marca, teléfono en el texto)
no se muestran solas — solo aparecen si hay también señales duras.
Esto evita alertas alarmantes en correos legítimos que mencionan palabras comunes.

Las señales duras (dominio falso, pedido de OTP, fraude del jefe) siempre aparecen
porque indican amenaza real.

---

### Capa 2 — Modelo de machine learning (`server.py` + `models/`)

El motor de reglas detecta señales técnicas, pero no entiende el sentido del texto.
Un correo puede no tener ninguna URL sospechosa y aun así ser una estafa cuidadosamente escrita.

Para eso existe la capa de ML: un clasificador entrenado sobre ~46.000 textos reales.

**Qué tipo de modelo es:**

Un clasificador lineal basado en SGD (Stochastic Gradient Descent) ajustado para entregar probabilidades más estables.
No es una red neuronal — es un modelo lineal eficiente entrenado sobre representaciones numéricas del texto usando TF-IDF.

**Qué es TF-IDF:**

Term Frequency - Inverse Document Frequency. Una forma de representar texto como números.

- **TF** — qué tan seguido aparece una palabra en este texto
- **IDF** — qué tan rara es esa palabra en todos los textos del dataset

Si una palabra aparece mucho aquí pero poco en el dataset general, tiene peso alto.
Si aparece en todos lados ("el", "de", "que"), tiene peso bajo.
Así el modelo aprende a enfocarse en las palabras que realmente distinguen
un phishing de un correo legítimo.

**Word n-grams y char n-grams:**

El modelo analiza el texto de dos formas distintas:

- **Word n-grams (1-2)**: palabras individuales y pares. "expira hoy" es más
  revelador que "expira" o "hoy" por separado.
- **Char n-grams (3-4)**: secuencias de caracteres dentro de las palabras.
  Captura variaciones como "urgente", "urgentee" o "urg3nte".

**Limitación importante:** el modelo fue entrenado mayoritariamente en inglés.
Su rendimiento en español de LATAM es menor — tasa de falsos positivos ~9.6%
en español versus ~2.3% en inglés.

Las métricas son aproximadas y corresponden a pruebas exploratorias
realizadas durante el desarrollo del proyecto.

---

### Capa 3 — Sistema híbrido (`hybrid.js`)

El motor JS y el modelo ML a veces no están de acuerdo.
¿A cuál hacerle caso? ¿Cuánto puede cambiar el ML el resultado del JS?

La capa híbrida resuelve eso con un **evidence gate** — una compuerta que decide
cuánta influencia puede tener el ML según el contexto:

```
blocked  → texto muy corto, sin señales JS
           el ML no actúa

partial  → hay señales de legitimidad (newsletter, OTP oficial)
           el ML solo puede bajar el score, no subirlo

semantic → no hay señales técnicas, solo texto
           el ML puede dar un boost pequeño si está muy seguro (conf ≥ 0.85)

open     → hay señales JS activas
           el ML puede subir o bajar el score según su confianza
```

**Por qué este diseño:**

Sin el gate, el ML podría marcar como sospechoso un texto corto y ambiguo
solo porque su distribución de palabras se parece superficialmente a algo
en su dataset. El gate evita ese tipo de falso positivo.

---

## Por qué el score puede sumar más de 100

En el log técnico verás señales que suman 270 puntos o más.
El score final igual queda en 100.

Eso es correcto — cada señal aporta su peso de forma independiente
y el resultado se capea al máximo. El log muestra los pesos para
entender qué activó cada señal, no para que sumen el total.

---

## Cómo leer el código si eres estudiante

El mejor orden para entender el sistema desde cero:

1. **`config.json`** — solo números, pero definen todos los umbrales del sistema.
   Entender qué significa cada uno es entender cómo está calibrado el detector.

2. **`app.js`** — el motor JS. Las secciones `SECCIÓN 1` (señales) y
   `SECCIÓN 2` (correlaciones) son el núcleo. Las señales individuales son
   lo más parecido al scanner Bash — pero con jerarquía y pesos diferenciados.

3. **`hybrid.js`** — lee `computeEvidenceGate()` primero, luego
   `computeFinalScore()`. Esas dos funciones son el corazón de la arquitectura híbrida.

4. **`server.py`** — es corto. Lee cómo carga el modelo y responde las peticiones.

5. **`index.html`** — la interfaz. El JS de presentación está al final del archivo,
   separado de la lógica de detección.

---

## Limitaciones conocidas

- Falsos positivos ~7% en correos de marketing legítimo agresivo
- FPR en español ~9.6% — el ML fue entrenado principalmente en inglés
- No detecta phishing por imagen ni por QR
- No funciona en tiempo real — analiza textos pegados manualmente
- Requiere Python para la capa ML — sin él, solo funciona el motor JS
- El bypass es posible — un atacante que conozca las reglas puede evitarlas

---

## Instalación

```bash
git clone https://github.com/fivur-cs/notphish.git
cd notphish
pip install scikit-learn joblib flask
python server.py
```

Luego abre `index.html` en el navegador.

Sin Python: abre `index.html` directo. Funciona solo con la capa JS.

---

## Estructura

```
notphish/
├── index.html       # Interfaz web
├── app.js           # Motor de reglas JS
├── hybrid.js        # Sistema híbrido — evidence gate y fusión JS + ML
├── hints.js         # Textos educativos por tipo de amenaza
├── server.py        # Servidor Flask para el modelo ML
├── config.json      # Umbrales y parámetros
└── models/
    ├── primary_model_candidate.joblib
    └── subcategory_model_candidate.joblib
```

---

## El punto de partida

[`social-engineering-scanner`](https://github.com/fivur-cs/social-engineering-scanner)
es el proyecto anterior — detección basada en palabras y reglas fijas.
Leer los dos en orden muestra qué problema intenta resolver cada nueva capa.

---

## Roadmap

- [ ] Extensión para navegador
- [ ] Soporte para imágenes con OCR
- [ ] Más entrenamiento en español LATAM
- [ ] Versión móvil
- [ ] Mejoras en explicabilidad

---

## Tecnologías

HTML · CSS · JavaScript vanilla · Python · scikit-learn · Flask · TF-IDF · SGD

---

## Licencia

MIT

---

*Fabián Ubilla — estudiante de ingeniería informática y ciberseguridad*
