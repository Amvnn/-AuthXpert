import express from 'express';
import {
    registerUser,
    loginUser,
    verifyOTP,
    resendOTP,
    forgotPassword,
    ForgotPasswordVerifyOTP,
    resetPassword,
    updatePassword,
    updateMe,
    deleteMe,
    getMe
} from '../controllers/Auth_controller.js';
import { protect} from '../utils/Auth_Utils.js';

const router = express.Router();

// Public routes
router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/verify-otp', verifyOTP);
router.post('/resend-otp', resendOTP);
router.post('/forgot-password', forgotPassword);
router.post('/verify-reset-otp', ForgotPasswordVerifyOTP);
router.patch('/reset-password/:token', resetPassword);

// Protected routes (require authentication)
router.use(protect);

router.get('/me', getMe);
router.patch('/update-password', updatePassword);
router.patch('/update-me', updateMe);
router.delete('/delete-me', deleteMe);

// Admin routes
// router.use(restrictTo('Admin'));
// Add admin-only routes here

export default router;