// models/user.js

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config/config').get(process.env.NODE_ENV);

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    firstname: {
        type: String
    },
    lastname: {
        type: String
    },
    token: {
        type: String
    }
});

// Hashear contraseña antes de guardar
userSchema.pre('save', async function () {
    if (this.isModified('password')) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }
});

// Comparar contraseña para el login
userSchema.methods.comparePassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Generar token
userSchema.methods.generateToken = async function () {
    const token = jwt.sign(this._id.toHexString(), config.SECRET);
    this.token = token;
    return await this.save();
};

// Buscar usuario por token
userSchema.statics.findByToken = async function (token) {
    try {
        const decoded = jwt.verify(token, config.SECRET);
        return await this.findOne({ _id: decoded, token: token });
    } catch (err) {
        return null;
    }
};

// Eliminar token para logout
userSchema.methods.deleteToken = async function () {
    return await this.updateOne({ $unset: { token: 1 } });
};

const User = mongoose.model('User', userSchema);

module.exports = User;