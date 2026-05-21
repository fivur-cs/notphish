# NotPhish

Proyecto de aprendizaje sobre detección de phishing.

---

## Cómo fue construido — y por qué importa decirlo

Soy estudiante de ingeniería informática. A la fecha de este proyecto,
mis conocimientos de programación son básicos: fundamentos, nada más.

De Python, JavaScript y de entrenar modelos de ML solamente tengo los 
conceptos básicos, aún estoy lejos de poder generar proyectos desde
cero por mi propia cuenta.

Este proyecto fue construido usando Claude (Anthropic) como herramienta
principal. Claude propuso la arquitectura, escribió el código, diseñó
el sistema híbrido y tomó la mayoría de las decisiones técnicas.

Mi rol fue distinto: definir qué quería explorar, evaluar cada propuesta,
rechazar lo que no se sentía bien, entender — a mi ritmo — qué estaba
pasando en cada paso, y dirigir el enfoque hacia algo que tuviera sentido
para mí.

No lo publico como algo que "hice yo solo". Lo publico siendo honesto
sobre cómo fue, porque creo que ese proceso también tiene valor.

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

Empecé por una pregunta simple:

> **¿cómo sabe un programa que un mensaje es una estafa?**

Primero construí [`social-engineering-scanner`](https://github.com/fivur-cs/social-engineering-scanner)
— un script Bash que busca palabras sospechosas con `grep`. Funciona
para casos obvios, pero tiene falsos positivos altos y se evade fácil.

NotPhish nació para responder la pregunta que ese script deja abierta:
¿qué se necesita para ir más allá de las reglas fijas?

No tenía respuesta cuando empecé. La fui encontrando en el proceso.

---

## Para quién es la interfaz

La interfaz la pensé para personas con baja alfabetización digital:
lenguaje simple, sin tecnicismos, orientada a que cualquier persona —
especialmente adultos mayores — pueda entender qué encontró el análisis
y qué hacer.


---

## Qué hace

- Analiza texto libre: correos, SMS, WhatsApp, cualquier mensaje
- Detecta señales técnicas y semánticas de manipulación
- Muestra un puntaje de 0 a 100 con explicación en lenguaje simple
- Recomienda qué hacer según el nivel de riesgo
- Todo el análisis ocurre localmente — ningún texto sale de tu equipo

---

## Cómo funciona por dentro

Esta parte es técnica. La entiendo a nivel conceptual —
no a nivel de poder escribirla yo solo.

NotPhish tiene tres capas que trabajan juntas.

---

### Capa 1 — Motor de reglas JavaScript (`app.js`)

Analiza el texto buscando señales técnicas concretas, no solo palabras sueltas.

Detecta dominios que imitan marcas conocidas, URLs acortadas u ofuscadas,
pedidos de OTP, patrones de fraude corporativo (BEC), y señales de
ingeniería social como urgencia artificial o suplantación de autoridad.

Cada señal tiene un peso numérico. El score final se capea a 100 —
si un texto activa señales por 270 puntos, el resultado igual es 100.
Las señales individuales del log técnico muestran los pesos para
entender qué activó cada cosa, no para que sumen el total.

---

### Capa 2 — Modelo de machine learning (`server.py` + `models/`)

El motor de reglas detecta señales técnicas, pero no entiende el sentido
del texto. Un correo puede no tener ninguna URL sospechosa y aun así
ser una estafa escrita con cuidado.

Para eso existe la capa de ML: un clasificador entrenado sobre ~46.000
textos reales que le facilité a Claude — phishing, SMS scam, newsletters y correos legítimos.

Usa TF-IDF para representar el texto como números. TF-IDF le da más
peso a las palabras que son frecuentes en este mensaje pero raras en
el dataset general — las que realmente distinguen un phishing de un
correo normal.

El modelo devuelve una probabilidad: qué tan seguro está de que el
texto es legítimo o scam. Esa confianza es lo que usa la capa siguiente.

**Limitación importante:** fue entrenado mayoritariamente en inglés.
Su rendimiento en español de LATAM es menor — tasa de falsos positivos
~9.6% en español versus ~2.3% en inglés.

---

### Capa 3 — Sistema híbrido (`hybrid.js`)

El motor JS y el modelo ML a veces no están de acuerdo.
¿A cuál hacerle caso? ¿Cuánto puede cambiar el ML el resultado del JS?

La capa híbrida resuelve eso con un **evidence gate** — una compuerta
que decide cuánta influencia puede tener el ML según el contexto:

- **blocked** → texto muy corto, sin señales JS. El ML no actúa.
- **partial** → hay señales de legitimidad. El ML solo puede bajar el score.
- **semantic** → no hay señales técnicas. El ML puede dar un boost pequeño.
- **open** → hay señales JS activas. El ML puede subir o bajar el score.

Sin este gate, el ML podría marcar como sospechoso un mensaje corto
y ambiguo solo porque su distribución de palabras se parece a algo
en su dataset. El gate evita ese tipo de falso positivo.

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
# Luego abre index.html en el navegador
```

Sin Python: abre `index.html` directo. Funciona solo con el motor JS.

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
es el proyecto anterior — un script Bash simple que muestra exactamente
por qué las reglas solas no son suficientes. Leer los dos en orden
muestra qué problema resuelve cada capa.

---

## Roadmap

- [ ] Extensión de navegador para Gmail
- [ ] Soporte para imágenes con OCR
- [ ] Modo offline completo sin Python
- [ ] Más datos de entrenamiento en español de LATAM
- [ ] Versión móvil

---

## Tecnologías

HTML, CSS, JavaScript vanilla · Python, scikit-learn, Flask · SGD + TF-IDF

---

## Licencia

MIT

---

*fivur, estudiante de ingeniería informática y ciberseguridad*
