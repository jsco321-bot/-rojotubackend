const { authUserS, recuperarContrasenaS, cambiarContrasenaS, agregarCorreoS, userHasChangedIdentityS, authUserS_B} = require("../../domain/service/service.user");


const authUserC = async (req, res) => {
    const response = await authUserS(req, res);
    res.status(response.code).json(response)
}

const authUserC_B = async (req, res) => {
    const response = await authUserS_B(req, res);
    res.status(response.code).json(response)
}

/** Cambia si usurario ha registrado identidad de genero */
const userHasChangedIdentityC = async (req, res) => {
    const { identidad } = req.body;
    if (req.header("token")) {
        if (identidad) {
            const response = await userHasChangedIdentityS(req, identidad);
            res.status(response.code).json(response)
        } else {
            let response = {
                code: 400,
                message: "Faltan campos!",
                data: []
            }
            return res.status(response.code).json(response);
        }
    }else{
        let response = {
            code: 400,
            message: "Faltan token de autenticación",
            data: []
        }
        return res.status(response.code).json(response);
    }
    
}

const agregarCorreoC = async (req, res) => {
    const response = await agregarCorreoS(req, res);
    res.status(response.code).json(response)
}

const recuperarContrasenaC = async (req, res) => {
    const { usuario } = req.body;
    if (usuario) {
        const response = await recuperarContrasenaS(usuario);
        return res.status(response.code).json(response);
    } else {
        let response = {
            code: 400,
            message: "Faltan campos!",
            data: []
        };
        return res.status(response.code).json(response);
    }
}

const cambiarContrasenaC = async (req, res) => {
    const { usuario, codigo, nueva_contrasena } = req.body;
    if (usuario) {
        const response = await cambiarContrasenaS(usuario, codigo, nueva_contrasena);
        res.status(response.code).json(response);
    } else {
        let response = {
            code: 400,
            message: "Faltan campos!",
            data: []
        };
        return res.status(response.code).json(response);
    }
}

module.exports = { authUserC, recuperarContrasenaC, cambiarContrasenaC, agregarCorreoC, userHasChangedIdentityC,authUserC_B};
