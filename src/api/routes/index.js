const express = require("express");
const { authUserC,authUserC_B, recuperarContrasenaC, cambiarContrasenaC, reportUsuariosC, tabPedidosC, reportZonasC, reportLogsC, userHasChangedIdentityC } = require("../../api/controllers/controller.user");
const { validateTokenC } = require("../controllers/controller.auth");
const routers = express.Router();
const bodyParser = require('body-parser');
const { enviarCarritoC, buscarCarritoC, agregarPrendaC, quitarPrendaC } = require("../controllers/controller.carrito");
const { listarPrendasC, buscarPrendaC } = require("../controllers/controller.prendas");
const { reportLogsUsersC, reportLogsDayUsersC, reportLogsCartsDayC } = require("../controllers/controller.logs");

routers.get("/", (_req, res) => {
    res.status(200).json({ message: 'Raiz del API', code: 200, data: {}, error: false })
})

/*Usuario*/
routers.post('/authUser', bodyParser.json(), authUserC)
routers.post('/authUser_B', bodyParser.json(), authUserC_B)
routers.post('/validateToken', bodyParser.json(), validateTokenC)
//routers.post('/actualizarIdentidad', bodyParser.json(), userHasChangedIdentityC)

/*Contraseña*/
routers.post('/cambiarContrasena', bodyParser.json(), cambiarContrasenaC)
routers.post('/solicitarCodigo', bodyParser.json(), recuperarContrasenaC)

/*Prendas*/
routers.post('/listarPrendas', bodyParser.json(), listarPrendasC)
routers.post('/buscarprenda', bodyParser.json(), buscarPrendaC)

/*Carrito*/
routers.post('/buscarCarrito', bodyParser.json(), buscarCarritoC)
routers.post('/enviarCarrito', bodyParser.json(), enviarCarritoC)

routers.post('/agregarPrenda', bodyParser.json(), agregarPrendaC)
routers.post('/quitarPrenda', bodyParser.json(), quitarPrendaC)

/*KPIs*/
// 3 .kpi de ingreso de personas que han ingresaso y quienes no, separado por hombre, mujere y sede
routers.post('/reports/user', bodyParser.json(), reportLogsUsersC)
// 1, kpi de ingreso de personal por dia
routers.post('/reports/user/day', bodyParser.json(), reportLogsDayUsersC)
// 1, kpi de ingreso de personal por dia
routers.post('/reports/carritos/day', bodyParser.json(), reportLogsCartsDayC)

module.exports = routers;
