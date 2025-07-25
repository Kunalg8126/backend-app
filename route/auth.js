const express = require("express");
const router = express.Router();
const {sendOtp, verifyOtp, register, login, profile, forgotPassword, resetPassword} = require('../controllers/authController');
const authMiddleware = require("../middleware/authMiddleware");

router.post('/send-otp', sendOtp);
router.post('/verify-otp', verifyOtp);
router.post('/register', register);
router.post('/login', login);
router.get("/profile",authMiddleware, profile);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password/:token', resetPassword);



module.exports = router;

