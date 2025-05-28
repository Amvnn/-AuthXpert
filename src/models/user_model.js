import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import validator from "validator";
import {v4 as uuidv4} from 'uuid';

const userSchema = new mongoose.Schema({
    UserID :{
        type:String,
        default: uuidv4,
        unique: true,
        required:true
    },
    name:{
        type: String,
        required:[true,'Please provide your name']
    },
    email:{
        type: String,
        required:[true,'Please provide your email'],
        unique:true,
        trim:true,
        validate:[validator.isEmail,'Please provide a valid email']
    },
    password:{
        type:String,
        required:[,'Please provide your password'],
        minlength:8,
        select:false
    },
    phone:{
        type:String,
        required:[true,'Please provide your phone number'],
        unique: true,
        validator:{
            validator:function(v){
                return /^\d{10}$/.test(v);
            },
            message:"Phone number must be 10 digits"
        },
        validate(v){
            if(v.length !== 10){
                throw new Error('Phone number must be 10 digits');
            }
        }
    },
    isPhoneVerified:{
        type:Boolean,
        default:false
    },
    isEmailVerified:{
        type:Boolean,
        default:false
    },
    otp:{
        type:String,
        select:false
    },
    otpExpires:{
        type:Date,
        select:false
    },
    otpAttempts:{
        type:Number,
        deafult:0,
        select:false
    },
    lastOtpSentAt:{
        type:Date,
        select:false
    },
    passwordChangedAt:Date,
    passwordResetToken:String,
    passwordResetExpiry:Date,
    active:{
        type:Boolean,
        default:true,
        select:false
    }
},{
    timestamps:true
});

// Pre-Hook : HASH the password befaore any save
userSchema.pre('save',async function(next){
    if(!this.isModified('password'))return next();
    this.password = await bcrypt.hash(this.password,12);
    next();
});


// Update passwordChangedAt when password is modified
userSchema.pre('save',function(next){
    if(!this.isModified('password')||this.isNew) return next();
    this.passwordChangedAt = Date.now() - 1000;
    next();
});

// Password comparison
userSchema.methods.correctPassword = async function(candidatePassword,userPassword){
    return await bcrypt.compare(candidatePassword,userPassword);
};

// password was changes after token was issued
userSchema.methods.changedPasswordAfter = function(JWTTimestamp){
    if(this.passwordChnageAt){
        const changedTimestamp = parseInt(this.passwordChangedAt.getTime()/1000,10);
        return JWTTimestamp < changedTimestamp;
    }
    return false;
};

// Create and save password reset token
userSchema.methods.createPasswordResetToken = function(){
    const resetToken = crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

    this.passwordResetExpires = Date.now() + 10*60*1000;
    return resetToken;
};

//Index for OTP expiration
userSchema.index({ otpExpires:1},{expireAfterSeconds:0});
const User = mongoose.model('User',userSchema);

export default User;