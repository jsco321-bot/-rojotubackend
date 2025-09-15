const { buscarCarritoR, quitarPrendaR, agregarPrendaR, enviarCarritoR } = require("../repository/repository.carrito.js");
const { searchUserR } = require('../repository/repository.user.js');
const { authS, decode } = require('./service.auth.js');
const ejs = require("ejs");
const nodemailer = require("nodemailer");
const path = require('path');

const buscarCarritoS = async (req, res) => {
    let response = {
        code: "",
        message: "",
        data: "",
        token: ""
    }

    const isValid = await authS(req.header("token"));
    if ((isValid).code == 200) {
        const d = await decode(req.header("token"));
        const usuario = isValid;
        const carrito = await buscarCarritoR(d.usuario);

        if (carrito) {
            response.code = 200
            response.message = "autorizado"
            response.data = carrito
            response.token = usuario.token;
        } else {
            response.code = 200
            response.message = "No se ha encontrado un carrito con este usuario!"
            response.data = []
            response.token = usuario.token;
        }

    } else {
        response.code = 401
        response.message = "No autorizado o sesion expirada"
        response.data = []
    }
    return response
}

const agregarPrendaS = async (req, id_prenda, talla, dia = "") => {
    let response = {
        code: "",
        message: "",
        data: ""
    }

    const isValid = await authS(req.header("token"));
    const d = await decode(req.header("token"));
    if ((isValid).code == 200) {
        const usuario = isValid;
        const prenda = await agregarPrendaR(d.usuario, id_prenda, talla, dia);
        if (prenda) {
            response.code = 200
            response.message = "Exito!"
            response.data = prenda
            response.token = usuario.token;
        } else {
            response.code = 200
            response.message = "No se puede agegar esta prenda al carrito"
            response.data = []
            response.token = usuario.token;
        }
    } else {
        response.code = 401
        response.message = "No autorizado o sesion expirada"
        response.data = []
    }

    return response
}

const quitarPrendaS = async (req, id_prenda) => {
    let response = {
        code: "",
        message: "",
        data: ""
    }

    const isValid = await authS(req.header("token"));
    const d = await decode(req.header("token"));
    if ((isValid).code == 200) {
        const usuario = isValid;
        const pedido = await quitarPrendaR(d.usuario, id_prenda);
        if (pedido) {
            response.code = 200
            response.message = "autorizado"
            response.data = "Exito"
            response.token = usuario.token;
        } else {
            response.code = 200
            response.message = "Error! No se ha encontrado la prenda!"
            response.data = []
            response.token = usuario.token;
        }
    } else {
        response.code = 401
        response.message = "No autorizado o sesion expirada"
        response.data = []
    }

    return response
}

const enviarMailCarritoS = async (correoUser, subject, texto, nombre_usuario, usuario) => {
    
    
    let lista_prendas = await prepMailCarrioS(usuario);

    var jsonPath = path.join(__dirname, '..', 'assets', 'index.html');
    var header = path.join(__dirname, '..', 'assets', 'header.jpg');
    var footer = path.join(__dirname, '..', 'assets', 'footer.jpg');

    let newHmtl = "";
    ejs.renderFile(jsonPath, {
        usuario: nombre_usuario,
    }, (err, data) => {
        if (err) {
            console.log(err);
        } else {
            newHmtl = data;
        }
    });

    newHmtl = newHmtl.replace("<prendas>", lista_prendas)

    const mailgun = new Mailgun(formData);
           const mg = mailgun.client({
           username: "api",
           key: process.env.EMAIL_PASSWORD 
           });
   
           mg.messages
           .create("mg.coleccionrojotu.com.co", { 
           from: "Admin <admin@coleccionrojotu.com>",
           to: correoUser,
           subject: subject,
           html: newHmtl,
           attachments:
               [
                   {
                       filename: 'header.jpg',
                       path: header,
                       cid: 'header'
                   },
                   {
                       filename: 'footer.jpg',
                       path: footer,
                       cid: 'footer'
                   }
               ]
           })
           .then(msg => console.log("Correo enviado:", msg))
           .catch(err => console.error("Error al enviar:", err));

    return true
}

const prepMailCarrioS = async (usuario) => {
    try {
        
        const carrito = await buscarCarritoR(usuario);
        let prendasHTML = ""
        for (let i = 0; i < carrito.carrito.length; i++) {
            if (carrito.carrito[i].dia && carrito.carrito[i].talla) {
                prendasHTML = prendasHTML +`<p>🛒- ${carrito.carrito[i].prenda.nombre_prenda}, Talla: ${carrito.carrito[i].talla}, Dia: ${carrito.carrito[i].dia}<p/>`
            }else{
                prendasHTML = prendasHTML +`<p>🛒- ${carrito.carrito[i].prenda.nombre_prenda}<p/>`
            }
        }
        return prendasHTML
    } catch (error) {
        console.log(error);
       return ""
    }

}

const enviarCarritoS = async (req, res) => {
    let response = {
        code: "",
        message: "",
        data: [],
        token: ""
    }

    const isValid = await authS(req.header("token"));
    const d = await decode(req.header("token"));
    const usuario = isValid;
    if ((isValid).code == 200) {
        const pedidoEnviado = await enviarCarritoR(d.usuario);
        if (pedidoEnviado) {
            try {
                const user = await searchUserR(d.usuario);
                const mailEnviado = await enviarMailCarritoS(user.correo, "Coleccion RojoTu", `Tu pedido ha sido enviado exitosamente!`, user.nombre, d.usuario)
                if (mailEnviado) {
                    response.code = 200,
                    response.message = "¡Se ha enviado tu pedido exitosamente!"
                    response.token = usuario.token
                    response.data = []
                } else {
                    response.code = 401,
                    response.message = "Ha ocurrido un error enviado el carrito"
                    response.token = usuario.token
                    response.data = []
                }
            } catch (error) {
                response.code = 401,
                response.message = "Ha ocurrido un error!"
                response.token = usuario.token
                response.data = []
            }
        } else {
            response.code = 201
            response.message = "No se puede enviar el carrito actualmente!"
            response.token = usuario.token
            response.data = []
        }
    } else {
        response.code = 401
        response.message = "No autorizado"
    }
    return response
}

module.exports = { agregarPrendaS, quitarPrendaS, buscarCarritoS, enviarCarritoS }
