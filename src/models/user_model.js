import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import validator from "validator";
import {v4 as uuidv4} from 'uuid';

const userSchema = new mongoose.Schema({
    UserID :{
        type:String,
        default: () => uuidv4(),
        unique: true,
        required:true
    },
    name:{
        type: String,
        required:[true,'Please provide your name']
    },
    email: { 
        type: String, 
        required: true,
         unique: true ,
         lowercase : true,
         trim : true,
         validate:{
            validator: function(v){
                return /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(v);
            },
            message : props => `${props.value} is not a valid email!`
         }
        },

        password: { 
            type: String,
             required: function(){
                return this.authType === 'local';
             }
            },
        phone: {
                type: String,
                 required: false,
                  unique: true,
                  sparse: true 
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
    },
    otpExpires:{
        type:Date,
    },
    otpResendCount: { 
        type: Number,
         default: 0 
        },
    otpAttempts:{
        type:Number,
        deafult:0,
    },
    lastOtpSentAt:{
        type:Date,
    },
    resetPasswordOtp: {
        type: String
    },
    resetPasswordOtpExpires: {
        type: Date
    },
    isResetPasswordOtpVerified: {
      type: Boolean,
      default: false
    },
    resetPasswordVerifiedAt: {
        type: Date
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

// Password comparison for (login)
userSchema.methods.comparePassword = async function (candidatePassword) {
    if(this.authType == 'local' && this.password){
        return await bcrypt.compare(candidatePassword, this.password);
    }
    return false;
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