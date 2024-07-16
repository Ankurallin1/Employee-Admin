import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { z } from 'zod';
import { toast } from 'react-toastify';

const schema = z.object({
  name: z.string().min(2, "Name length must be more 2").max(50),
  email: z.string().email('Invalid email format'),
  password: z.string().min(6, 'Password must be at least 6 characters long'),
});

const RegisterPage = () => {

  const navigate = useNavigate();
  const { registerUser } = useAuth();
  const { register, handleSubmit, formState: { errors } } = useForm();
  console.log(process.env.REACT_APP_API_URL);
  const onSubmit = async (data) => {
    try {
      schema.parse(data);

      const success = await registerUser(data);
      if (success) {
        navigate('/verify-email');
      }
    } catch (error) {
      toast.error(error.errors[0].message);
    }
  };

  return (
    <div className='container1'>
      <h2>Register</h2>
      <form onSubmit={handleSubmit(onSubmit)}>
        <input type="text" {...register("name")} placeholder="Name" />
        <input type="email" {...register("email")} placeholder="Email" />
        <input type="password" {...register("password")} placeholder="Password" />
        <button type="submit">Register</button>
      </form>
      <p>Already have an account? <Link to='/login'>Login</Link></p>
    </div>
  );
};

export default RegisterPage;
