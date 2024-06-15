import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { z } from 'zod';
import { toast } from 'react-toastify';

const schema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(6, 'Password must be at least 6 characters long'),
});

const LoginPage = () => {
  const navigate = useNavigate();
  const { login } = useAuth();
  const { register, handleSubmit, formState: { errors } } = useForm();
  const [errorMessage, setErrorMessage] = useState('');

  const onSubmit = async (data) => {
    
    try {
      schema.parse(data);

      const success = await login(data.email, data.password);
      if (success) {
        navigate('/');
      }
    } catch (error) {
      toast.error(error.errors[0].message);
    }

    
  };

  return (
    <div className='container1'>
      <h2>Login</h2>
      <form onSubmit={handleSubmit(onSubmit)}>
        <input type="email" {...register("email")} placeholder="Email" />
        <input type="password" {...register("password")} placeholder="Password" />
        <button type="submit">Login</button>
      </form>
      <p> <Link to='/forgot-pass'>Forgot password?</Link></p>
      <p>Not Registered yet? <Link to='/userregister'>Register</Link></p>
    </div>
  );
};

export default LoginPage;
