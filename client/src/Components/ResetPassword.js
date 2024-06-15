import React from 'react';
import { useForm } from 'react-hook-form';
import { useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { z } from 'zod';
import { toast } from 'react-toastify';
const ResetPassword = () => {
    const { ResetPassword } = useAuth();
    const { id } = useParams();
    const navigate = useNavigate();
    const Schema = z.object({
        password: z.string().min(6, "Password must be of 6 digit atleast")
    })
    const { register, handleSubmit } = useForm();
    const onSubmit = async (data) => {
        try {
            Schema.parse(data);
            const sucess = await ResetPassword(data.password, id);
            if (sucess) {
                navigate('/');
            }

        } catch (error) {
            toast.error(error.errors[0].message);
        }
    }
    return (
        <div className='forgot-container'>
            <h1>Reset Password</h1>
            <form onSubmit={handleSubmit(onSubmit)}>
                <input
                    type="password"
                    {...register("password")}
                    placeholder="Enter your new password"
                />
                <button type="submit" >Submit</button>
            </form>
        </div>
    );
};

export default ResetPassword;