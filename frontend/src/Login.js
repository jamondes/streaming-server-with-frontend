import React, { useState } from 'react';
import { TextField, Button, Typography } from '@mui/material';
import { useAuth } from './auth';
import { Link } from "react-router-dom";

const styles = {
  form: {
    display: 'flex',
    flexDirection: 'column',
    maxWidth: '300px',
    margin: '0 auto',
  },
  inputField: {
    marginBottom: '10px',
  },
};

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const auth = useAuth();
  const handleSubmit = (e) => {
    e.preventDefault();
    auth.signIn({ email, password }, setError)
  };

  return (
    <div>
      <Typography variant="h4" align="center" gutterBottom>
        Login
      </Typography>
      {error && (
        <Typography variant="body1" color="error" align="center" gutterBottom>
          {error}
        </Typography>
      )}
      <form style={styles.form} onSubmit={handleSubmit}>
        <TextField
          label="Email"
          type="email"
          style={styles.inputField}
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <TextField
          label="Password"
          type="password"
          style={styles.inputField}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <Button type="submit" variant="contained" color="primary">
          Login
        </Button>
        <p>Don't have an account? <Link to="/create-account">Create account</Link></p>
      </form>
    </div>
  );
};

export default Login;
