const { model, Schema } = require('mongoose');

const UserLoginSchema = new Schema(
    {
        name: {
            type: String,
            required: true,
        },
        email: {
            type: String,
            required: true,
            unique: true,
        },
        password: {
            type: String,
            required: true,
        },
        isAdmin: {
            type: Boolean,
            default: false,
        },
        imageURL: {
            type: String,
            default: null,
        },
        lastLogin: {
            type: Date,
        },
        imagePublicId: {
            type: String,
        },
        otp: {
            type: String,
        },
        otpExpires: {
            type: Date,
        },
        isVerified: {
            type: Boolean,
            default: false,
        },
        resetPasswordToken: {
            type: String,
        },
        resetPasswordExpires: {
            type: Date,
        },
    },
    {
        toJSON: {
            virtuals: true
        },
        toObject: {
            virtuals: true
        }
    }
);

const UserAuthModel = model('UserAuthModel', UserLoginSchema);

module.exports = { UserLoginSchema, UserAuthModel };
