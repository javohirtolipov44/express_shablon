const express = require('express');
const authController = require('../controllers/auth.controller');

const router = express.Router();

router.get('/login', authController.renderLogin);
router.post('/login', authController.login);

router.get('/register', authController.renderRegister);
router.post('/register', authController.register);

router.get('/logout', authController.logout);
router.get('/logged-out', authController.loggedOut);

router.get('/verify/:verifyToken', authController.verify);

router.get('/forgot-password', authController.renderForgotPassword);
router.post('/send-otp', authController.sendOtp);

router.get('/verify-otp', authController.renderVerifyOtp);
router.post('/verify-otp', authController.verifyOtp);

router.get('/reset-password', authController.renderResetPassword);
router.post('/reset-password', authController.resetPassword);

module.exports = router;
