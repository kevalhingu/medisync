const jwt = require("jsonwebtoken");
const adminAuth = require("./adminAuth");
const doctorAuth = require("./doctorAuth");
const patientAuth = require("./patientAuth");
const Patient = require('../../models/patient');
const mongoose = require("mongoose");
const Doctor = require("../../models/doctor");

function userAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    jwt.verify(token, process.env.SECRET_KEY, async (err, payload) => {
        if (err) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        req.sender = {
            "id": payload.id,
            "userType": payload.userType
        };

        if (payload.userType === "Admin") {
            // Uncomment if adminAuth logic is implemented
            // return adminAuth(req, res, next);
        } else if (payload.userType === "Doctor") {
            let doctor = await Doctor.findOne({ 'userId': mongoose.Types.ObjectId(req.sender.id) });
            if (!doctor) {
                return res.status(401).json({ message: 'Unauthorized: Doctor not found' });
            }
            req.sender.doctorId = doctor._id;
        } else if (payload.userType === "Patient") {
            let patient = await Patient.findOne({ 'userId': mongoose.Types.ObjectId(req.sender.id) });
            if (!patient) {
                return res.status(401).json({ message: 'Unauthorized: Patient not found' });
            }
            req.sender.patientId = patient._id;
        } else {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        next();
    });
}

module.exports = userAuth;
