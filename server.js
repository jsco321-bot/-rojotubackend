require("dotenv").config();
const express = require('express')
const cors = require("cors")
const app = express();
const routers = require('./src/api/routes/index');
const db = require('./src/domain/model/index');
const helmet = require("helmet");
const { useSwaggerDocs } = require('./swagger.js');
const allowedMethods = ['GET', 'POST']
const sqlInjectionPattern = /(\b(SELECT|INSERT|DELETE|UPDATE|DROP|UNION|--|;|'|"|\/\*|\*\/|xp_)\b)/i;
const allowlist = [process.env.CORS_ROJOTU, process.env.CORS_UAT, process.env.CORS_LOCAL, process.env.LOCAL_FRONT,process.env.CORS_ROJOTU_W]

db.sequelize.sync()
  .then(() => console.log("DB OK"))
  .catch(error => {
    console.error("DB Error:", error);
    // 👇 NO tumbar el proceso
  });

app.get("/health", (_, res) => res.sendStatus(204));

var corsOptionsDelegate = function (req, callback) {
  let corsOptions;
  const origin = req.header('Origin');

  if (!origin) {
    // ✅ Probes internos y llamadas servidor-servidor no envían Origin
    corsOptions = { origin: true };
  } else if (allowlist.indexOf(origin) !== -1) {
    corsOptions = { origin: true };
  } else {
    corsOptions = { origin: false };
  }
  callback(null, corsOptions);
};

function securityHeadersMiddleware(req, res, next) {
    res.removeHeader('Referrer-Policy');
    res.removeHeader('Permissions-Policy');
    res.removeHeader('Content-Security-Policy');
    res.removeHeader('X-Content-Type-Options');
    res.removeHeader('Strict-Transport-Security');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'geolocation=(false), camera=(false), microphone=(false)');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
}


app.use(securityHeadersMiddleware);

app.use(
    helmet(),
);



app.use(cors(corsOptionsDelegate));

app.disable('x-powered-by');
app.use("/api", (req, res, next) => {
    if (!allowedMethods.includes(req.method)) return res.status(405).json('Metodo No Permitido')
    return next()
});

function removeQueryParamsMiddleware(req, res, next) {
    const parsedUrl = new URL(req.protocol + '://' + req.get('host') + req.originalUrl);
    if (parsedUrl.search) {
        parsedUrl.search = '';
        return res.redirect(parsedUrl.toString());
    }
    next();
}

function sanitizeInput(input) {
    return input.replace(sqlInjectionPattern, '');
}

function sanitizeObject(obj) {
    for (const key in obj) {
        if (typeof obj[key] === 'string') {
            obj[key] = sanitizeInput(obj[key]);
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
            sanitizeObject(obj[key]);
        }
    }
}

function preventSQLInjection(req, res, next) {
    if (req.body && typeof req.body === 'object') {
        sanitizeObject(req.body);
    }
    function hasSQLInjection(value) {
        return sqlInjectionPattern.test(value);
    }
    for (const param in req.query) {
        if (hasSQLInjection(req.query[param])) {
            return res.status(400).send('Solicitud bloqueada');
        }
    }
    for (const param in req.body) {
        if (hasSQLInjection(req.body[param])) {
            return res.status(400).send('Solicitud bloqueada');
        }
    }
    next();
}

app.use(express.json());
app.use(removeQueryParamsMiddleware);
app.use(preventSQLInjection);
app.use("/api", routers);
if (process.env.SWAGGER_ON === true) {
    const swaggerJsdoc = require('swagger-jsdoc');
    const swaggerUi = require('swagger-ui-express');
    const { options } = require('./swagger-options.js');
    const swaggerSpec = swaggerJsdoc(options);
    app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec))
    app.get('/docs.json', (req, res) => {
        res.setHeader('Content-Type', 'application/json')
        res.send(swaggerSpec)
    })
}



const port = process.env.PORT || 8080;
app.listen(port, "0.0.0.0", () => console.log(`Listening on ${port}`));



module.exports = app;








