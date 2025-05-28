import User from '../models/user_model.js';
import { generateOTP, sendOTP, signToken, createSendToken, protect, restrictTo } from '../utils/Auth_Utils.js';
import { promisify } from 'util';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// Register a new user
export const registerUser = async (req, res, next) => {
    try {
        const { name, email, password, phone, role } = req.body;

        // 1) Check if user exists
        const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
        if (existingUser) {
            return res.status(400).json({
                status: 'error',
                message: 'User with this email or phone already exists'
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
            role: role || 'Student',
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
export const loginUser = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        // 1) Check if email and password exist
        if (!email || !password) {
            return res.status(400).json({
                status: 'error',
                message: 'Please provide email and password!'
            });
        }

        // 2) Check if user exists && password is correct
        const user = await User.findOne({ email }).select('+password');

        if (!user || !(await user.correctPassword(password, user.password))) {
            return res.status(401).json({
                status: 'error',
                message: 'Incorrect email or password'
            });
        }

        // 3) Check if user is verified
        if (!user.isPhoneVerified) {
            return res.status(401).json({
                status: 'error',
                message: 'Please verify your phone number first'
            });
        }

        // 4) If everything ok, send token to client
        createSendToken(user, 200, res);
    } catch (error) {
        next(error);
    }
};

// Verify OTP
export const verifyOTP = async (req, res, next) => {
    try {
        const { phone, otp } = req.body;
        console.log('Verifying OTP:', { phone, otp });  // Debug log

        // 1) Find user by phone and OTP
        const user = await User.findOne({
            phone,
            otp,
            otpExpires: { $gt: Date.now() }
        });

        console.log('Found user:', user ? user.email : 'No user found');  // Debug log

        // 2) If OTP is invalid or expired
        if (!user) {
            // Check if user exists but OTP is wrong/expired
            const userExists = await User.findOne({ phone });
            if (userExists) {
                console.log('User exists but OTP is invalid/expired. Stored OTP:', userExists.otp);  // Debug log
            }
            return res.status(400).json({
                status: 'error',
                message: 'Invalid or expired OTP'
            });
        }

        // 3) Mark user as verified
        user.isPhoneVerified = true;
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save({ validateBeforeSave: false });

        // 4) Send token to client
        createSendToken(user, 200, res);
    } catch (error) {
        next(error);
    }
};

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
export const getMe = (req, res, next) => {
    req.params.id = req.user.id;
    next();
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
