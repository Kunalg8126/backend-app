const bcrypt = require("bcryptjs");
const Otp = require("../model/otp");
const User = require("../model/User")
const nodemailer = require('nodemailer');
const jwt = require("jsonwebtoken");
const crypto = require('crypto')


const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();


//send-otp route
exports.sendOtp = async (req, res) => {

    const { email } = req.body;
    const otpCode = generateOtp();

    try {
        await Otp.create({ email, otp: otpCode });

        let transporter = nodemailer.createTransport({
            service: "Gmail",
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });


        await transporter.sendMail({
            to: email,
            subject: "your OTP code",
            text: `Your OTP is: ${otpCode}`
        });

        res.status(200).json({ message: 'OTP sent successfully' });
    }
    catch (error) {
        console.error("Error in sending OTP:", error);
        res.status(500).json({ message: 'OTP sent failed' })
    };

}

// verify route

exports.verifyOtp = async (req, res) => {
    const { email, otp } = req.body;

    try {
        const validOtp = await Otp.findOne({ email }).sort({ createdAt: -1 });

        if (!validOtp || validOtp.otp !== otp) {
            return res.status(400).json({ message: "OTP verification failed" });
        }

        await Otp.deleteMany({ email });

        res.status(200).json({ message: 'OTP verified successfully' });

    }
    catch (error) {
        res.status(500).json({ error: 'Verification failed' });
    }
};

// register route
exports.register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: "All fields are required" });
    }

    try {
        const existing = await User.findOne({ email });
        if (existing)
            return res.status(400).json({ message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ name, email, password: hashedPassword });

        res.status(200).json({ message: "User registered successfully" });
    }
    catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }

};

// login route
exports.login =  async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(404).json({ error: "User not found" })
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).json({ error: "Invalid Password" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
};


// Forgot Password Route
exports.forgotPassword = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found" });

        const token = crypto.randomBytes(32).toString("hex");
        user.resetToken = token;
        user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
        await user.save();

        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        const resetLink = `http://localhost:5173/reset-password/${token}`;

        await transporter.sendMail({
            to: user.email,
            subject: "Password Reset",
            html: `<p>Click <a href="${resetLink}">here</a> to reset your password. Link valid for 1 hour.</p>`,
        });

        res.json({ message: "Reset email sent" });
    } catch (err) {
        res.status(500).json({ error: "Failed to send email" });
    }
};


// Reset Password Route
exports.resetPassword = async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
        const user = await User.findOne({
            resetToken: token,
            resetTokenExpiry: { $gt: Date.now() },
        });

        if (!user) return res.status(400).json({ error: "Invalid or expired token" });

        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;

        await user.save();

        res.json({ message: "Password reset successful" });
    } catch (err) {
        console.log(err);

        res.status(500).json({ error: "Something went wrong" });
    }
};