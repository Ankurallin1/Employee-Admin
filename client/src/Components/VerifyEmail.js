import React, { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { z } from 'zod';
import { toast } from 'react-toastify';

const VerifyEmail = () => {
    const navigate = useNavigate();
    const { email , VerifyUser,ResendOTP } = useAuth(); 
    const [loading, setLoading] = useState(false);
    const [resendTimer, setResendTimer] = useState(30); 
    const Schema = z.object({
        otp: z.string().min(6, "OTP must be 6 digits")
    });
    const { register, handleSubmit} = useForm();

    useEffect(() => {
        let timerInterval;
        if (resendTimer > 0) {
            timerInterval = setInterval(() => {
                setResendTimer(prevTimer => prevTimer - 1);
            }, 1000);
        } else {
            clearInterval(timerInterval);
        }
        return () => clearInterval(timerInterval);
    }, [resendTimer]);

    const onSubmit = async (data) => {
        try {
            setLoading(true);
            Schema.parse(data);
            const success = await VerifyUser(email, data.otp);
            if (success) {
                navigate('/');
            }
        } catch (error) {
            toast.error(error.errors[0].message);
        } finally {
            setLoading(false);
        }
    }

    const handleResendOTP = () => {
        ResendOTP(email);
        setResendTimer(30); 
    }

    return (
        <div className="verify-email-container">
            <div className="verify-email-form-container">
                <h2 className="verify-email-title">Verify Your Email</h2>
                <p className="verify-email-text">Please enter the OTP sent to your email.</p>
                <form className="verify-email-form" onSubmit={handleSubmit(onSubmit)}>
                    <input
                        type="text"
                        {...register("otp")}
                        placeholder="Enter OTP"
                        className="verify-email-input"
                    />
                    <button type="submit" className="verify-email-button" disabled={loading}>
                        {loading ? 'Verifying...' : 'Verify'}
                    </button>
                </form>
              {resendTimer !== 0 && (
                    <p className="resend-otp-text">
                        Resend OTP in {resendTimer} seconds
                    </p>
                )}
                <button className={`resend-otp-button ${resendTimer!==0?'unactive':''}`} onClick={handleResendOTP} disabled={resendTimer !== 0}>
                    Resend OTP
                </button>
            </div>
        </div>
    );
};

export default VerifyEmail;
