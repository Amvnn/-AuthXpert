import User from '../models/user_model.js';
import { generateOTP, sendOTP, signToken, createSendToken, protect } from '../utils/Auth_Utils.js';
import { promisify } from 'util';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';


// Register a new user
export const registerUser = async (req, res, next) => {
    try {
        const { name, email, password, phone, role } = req.body;

        // 1) Check if user exists
        const existingPhoneUser = await User.findOne({ phone });
        if (existingPhoneUser) {
            return res.status(400).json({
                status: 'error',
                message: 'User with this phone number already exists'
            });
        }
        const existingEmailUser = await User.findOne({ email });
        if (existingEmailUser) {
            return res.status(400).json({
                status: 'error',
                message: 'User with this email already exists'
            });
        }

        // 2) Generate OTP
        const otp = generateOTP();
        const otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

        // 3) Create new user
        const newUser = await User.create({
            name,
            email,
            password,
            phone,
            otp,
            otpExpires:Date.now() + 10 * 60 * 1000
        });

        // 4) Send OTP (in production, implement actual SMS service)
        await sendOTP(phone, otp);

        // 5) Send response
        res.status(201).json({
            status: 'success',
            message: 'OTP sent to your phone number',
            data: {
                userId: newUser._id,
                phone: newUser.phone
            }
        });
    } catch (error) {
        next(error);
    }
};

// Login user
export const loginUser = async(req,res) =>{
    
    try {
        const { phone, password } = req.body;

        console.log("Login Request Details:", {
            phone,
            passwordLength: password.length,
        });

        // Input validation
        if (!phone || !password) {
            return res.status(400).json({ error: 'Phone and password are required' });
        }

        const user = await User.findOne({ phone, isPhoneVerified: true });
        if (!user) {
            const unverifiedUser = await User.findOne({ phone });
            if (unverifiedUser) {
                return res.status(400).send({ error: 'Account not verified. Please verify your phone number.' });
            }
        }
        const isMatch = await bcrypt.compare(password, user.password);
            
            console.log('Password Comparison:', {
                isMatch,
                passwordType: typeof password,
                hashedPasswordType: typeof user.password
            });

            if (!isMatch) {
                return res.status(400).json({ error: 'Invalid credentials' });
            }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        // Set the JWT as a cookie (with HttpOnly flag)
        res.cookie('token', token, {
           httpOnly: true, // cookie inaccessible to client-side scripts
           secure: false, // Use 'secure' flag in production
           sameSite: 'Strict', // Protect against CSRF attacks
       });


        res.status(200).send({ message: 'Login successful', token, id: user._id });
        console.log("Login successful:", { token, id: user._id });

    } catch (err) {
        console.error("Login error:", err);
        res.status(500).send({ error: 'Login failed', details: err.message });
    }
}

// Verify OTP
export const verifyOTP =  async (req, res) => {
    
    try {
        const { phone, otp } = req.body;
        const user = await User.findOne({ phone });
        console.log("User found:", user); // Log user info

         if (!user) {
            return res.status(404).send({ error: 'User not found. Please register first.' });
        }

        const MAX_ATTEMPTS = 5;
        if(user.otpAttempts >= MAX_ATTEMPTS ){
            return res.status(429).json({ message: 'Too many attempts. Please try again later.'})
        }

        // Check if the OTP matches and is not expired
        if (user.otp === otp && user.otpExpires > Date.now()) {
            // OTP is valid, mark the user as verified
            user.isPhoneVerified = true;
            user.otp = undefined; // Clear the OTP
            user.otpExpires = undefined; // Clear OTP expiration
            user.otpResendCount = 0; // Reset OTP resend count
            user.otpAttempts = 0

            await user.save(); // Save changes to the user

            // Respond with a success message
            return res.status(200).json({ message: 'OTP verified successfully! User is now registered.' });
        } else {
            
            // at every failure , otpAttemp will increament by 1.
            user.otpAttempts +=1;
            // OTP is invalid or expired
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }
    } catch (error) {
        // Handle any server errors
        return res.status(500).json({ message: 'An error occurred during OTP verification.', error: error.message });
    }
}
// Resend OTP
export const resendOTP = async (req, res, next) => {
    try {
        const { phone } = req.body;

        // 1) Find user by phone
        const user = await User.findOne({ phone });
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'No user found with this phone number'
            });
        }

        // 2) Generate new OTP
        const otp = generateOTP();
        user.otp = otp;
        user.otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
        await user.save({ validateBeforeSave: false });

        // 3) Send OTP (in production, implement actual SMS service)
        await sendOTP(phone, otp);

        res.status(200).json({
            status: 'success',
            message: 'OTP resent successfully'
        });
    } catch (error) {
        next(error);
    }
};

// Forgot password
export const forgotPassword = async (req, res, next) => {
    try {
        // 1) Get user based on POSTed email
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'There is no user with that email address.'
            });
        }

        // 2) Generate the random reset token
        const resetToken = user.createPasswordResetToken();
        await user.save({ validateBeforeSave: false });

        // 3) Send it to user's email (in production, implement email service)
        try {
            // In production, use a real email service
            console.log(`Password reset token: ${resetToken}`);
            
            res.status(200).json({
                status: 'success',
                message: 'Token sent to email!',
                resetToken // In production, don't send the token in response
            });
        } catch (err) {
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            await user.save({ validateBeforeSave: false });

            return res.status(500).json({
                status: 'error',
                message: 'There was an error sending the email. Try again later!'
            });
        }
    } catch (error) {
        next(error);
    }
};

// Verify OTP for password reset
export const ForgotPasswordVerifyOTP = async (req, res, next) => {
    try {
        const { email, otp } = req.body;

        // 1) Find user by email and OTP
        const user = await User.findOne({
            email,
            otp,
            otpExpires: { $gt: Date.now() }
        });

        // 2) If OTP is invalid or expired
        if (!user) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid or expired OTP'
            });
        }

        // 3) Generate reset token
        const resetToken = user.createPasswordResetToken();
        await user.save({ validateBeforeSave: false });

        res.status(200).json({
            status: 'success',
            message: 'OTP verified',
            resetToken
        });
    } catch (error) {
        next(error);
    }
};

// Reset password
export const resetPassword = async (req, res, next) => {
    try {
        // 1) Get user based on the token
        const hashedToken = crypto
            .createHash('sha256')
            .update(req.params.token)
            .digest('hex');

        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() }
        });

        // 2) If token has not expired, and there is user, set the new password
        if (!user) {
            return res.status(400).json({
                status: 'error',
                message: 'Token is invalid or has expired'
            });
        }

        // 3) Update changedPasswordAt property for the user
        user.password = req.body.password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save();

        // 4) Log the user in, send JWT
        createSendToken(user, 200, res);
    } catch (error) {
        next(error);
    }
};

// Update password (for logged-in users)
export const updatePassword = async (req, res, next) => {
    try {
        // 1) Get user from collection
        const user = await User.findById(req.user.id).select('+password');

        // 2) Check if POSTed current password is correct
        if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
            return res.status(401).json({
                status: 'error',
                message: 'Your current password is wrong.'
            });
        }

        // 3) If so, update password
        user.password = req.body.newPassword;
        await user.save();

        // 4) Log user in, send JWT
        createSendToken(user, 200, res);
    } catch (error) {
        next(error);
    }
};

// Get current user
export const getMe = async (req, res, next) => {
    try {
        // Since protect middleware already attached the user to req.user
        const user = await User.findById(req.user.id);
        
        res.status(200).json({
            status: 'success',
            data: {
                user
            }
        });
    } catch (error) {
        next(error);
    }
};

// Update user data (for logged-in users)
export const updateMe = async (req, res, next) => {
    try {
        // 1) Create error if user POSTs password data
        if (req.body.password) {
            return res.status(400).json({
                status: 'error',
                message: 'This route is not for password updates. Please use /updatePassword.'
            });
        }

        // 2) Filtered out unwanted fields names that are not allowed to be updated
        const filteredBody = {};
        const allowedFields = ['name', 'email', 'phone'];
        
        Object.keys(req.body).forEach(el => {
            if (allowedFields.includes(el)) filteredBody[el] = req.body[el];
        });

        // 3) Update user document
        const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
            new: true,
            runValidators: true
        });

        res.status(200).json({
            status: 'success',
            data: {
                user: updatedUser
            }
        });
    } catch (error) {
        next(error);
    }
};

// Delete current user (set active to false)
export const deleteMe = async (req, res, next) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { active: false });

        res.status(204).json({
            status: 'success',
            data: null
        });
    } catch (error) {
        next(error);
    }
};

// Get user by ID (admin only)
export const getUser = async (req, res, next) => {
    try {
        const user = await User.findById(req.params.id);
        
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'No user found with that ID'
            });
        }

        res.status(200).json({
            status: 'success',
            data: {
                user
            }
        });
    } catch (error) {
        next(error);
    }
};
