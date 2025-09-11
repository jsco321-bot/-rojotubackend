require("dotenv").config();

const express = require("express");
const app = express();

// 1) Endpoints ultra-tempranos (sin middlewares)
app.get("/health", (_, res) => res.sendStatus(204)); // usado por Cloud Run
app.get("/", (_, res) => res.send("OK"));            // opcional para dev


// 2) Empieza a escuchar YA (antes de cargar cosas pesadas)
const port = process.env.PORT || 8080;
app.listen(port, "0.0.0.0", () => console.log(`Listening on ${port}`));

// 3) Carga resto de dependencias (después de escuchar)
const cors = require("cors");
const helmet = require("helmet");
const routers = require("./src/api/routes/index");
const sqlInjectionPattern = /(\b(SELECT|INSERT|DELETE|UPDATE|DROP|UNION|--|;|'|"|\/\*|\*\/|xp_)\b)/i;

const allowlist = [
  process.env.CORS_ROJOTU,
  process.env.CORS_UAT,
  process.env.CORS_LOCAL,
  process.env.LOCAL_FRONT,
  process.env.CORS_ROJOTU_W
];

// 4) DB: conectar rápido; NO bloquees el arranque
let db;
try {
  db = require("./src/domain/model/index"); // Sequelize
  db.sequelize
    .authenticate()
    .then(() => {
      console.log("DB CONNECT OK");
      // Si necesitas sync, hazlo ya con el server arriba:
      // return db.sequelize.sync();
    })
    .then(() => console.log("DB READY"))
    .catch((error) => console.error("DB Error:", error));
} catch (e) {
  console.error("DB MODULE LOAD ERROR:", e);
}

// 5) Middlewares (ya con el server arriba)
function securityHeadersMiddleware(req, res, next) {
  res.removeHeader("Referrer-Policy");
  res.removeHeader("Permissions-Policy");
  res.removeHeader("Content-Security-Policy");
  res.removeHeader("X-Content-Type-Options");
  res.removeHeader("Strict-Transport-Security");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(false), camera=(false), microphone=(false)");
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
}

const corsOptionsDelegate = (req, callback) => {
  const origin = req.header("Origin");
  // Probes y llamadas server-to-server no traen Origin
  if (!origin || allowlist.includes(origin)) return callback(null, { origin: true });
  return callback(null, { origin: false });
};

const allowedMethods = ["GET", "POST"];

function removeQueryParamsMiddleware(req, res, next) {
  const parsedUrl = new URL(req.protocol + "://" + req.get("host") + req.originalUrl);
  if (parsedUrl.search) {
    parsedUrl.search = "";
    return res.redirect(parsedUrl.toString());
  }
  next();
}

function sanitizeInput(input) {
  return input.replace(sqlInjectionPattern, "");
}
function sanitizeObject(obj) {
  for (const key in obj) {
    if (typeof obj[key] === "string") obj[key] = sanitizeInput(obj[key]);
    else if (typeof obj[key] === "object" && obj[key] !== null) sanitizeObject(obj[key]);
  }
}
function preventSQLInjection(req, res, next) {
  if (req.body && typeof req.body === "object") sanitizeObject(req.body);
  const hasSQLInjection = (v) => sqlInjectionPattern.test(v);
  for (const param in req.query) if (hasSQLInjection(req.query[param])) return res.status(400).send("Solicitud bloqueada");
  for (const param in req.body) if (hasSQLInjection(req.body[param])) return res.status(400).send("Solicitud bloqueada");
  next();
}

app.disable("x-powered-by");
app.use(securityHeadersMiddleware);
app.use(helmet());
app.use(cors(corsOptionsDelegate));
app.use(express.json());
app.use(removeQueryParamsMiddleware);
app.use(preventSQLInjection);

app.use("/api", (req, res, next) => {
  if (!allowedMethods.includes(req.method)) return res.status(405).json("Metodo No Permitido");
  return next();
});
app.use("/api", routers);

// Swagger (las env vars en Cloud Run son strings)
if (String(process.env.SWAGGER_ON).toLowerCase() === "true") {
  const swaggerJsdoc = require("swagger-jsdoc");
  const swaggerUi = require("swagger-ui-express");
  const { options } = require("./swagger-options.js");
  const swaggerSpec = swaggerJsdoc(options);
  app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));
  app.get("/docs.json", (req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.send(swaggerSpec);
  });
}

module.exports = app;









