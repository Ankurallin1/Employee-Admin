import React, { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { z } from 'zod';
import { toast } from 'react-toastify';
const ForgotPassword = () => {
    const [check, setCheck] = useState(true);
    const { forgotPassword } = useAuth();
    const Schema = z.object({
        email: z.string().email("Invalid email address")
    })
    const { register, handleSubmit } = useForm();
    const onSubmit = async (data) => {
        try {
            Schema.parse(data);
            await forgotPassword(data.email);
            setCheck(false);
        } catch (error) {
            setCheck(true);
            toast.error(error.errors[0].message);
        }
    }
    return (
        <div className='forgot-container'>
            <h1>Forgot Password</h1>
            {check ?
                <form onSubmit={handleSubmit(onSubmit)}>
                    <input
                        type="email"
                        {...register("email")}
                        placeholder="Enter your email"
                    />
                    <button type="submit" >Submit</button>
                </form>
                : <h2>Password reset link sent to your email</h2>}
        </div>
    );
};

export default ForgotPassword;