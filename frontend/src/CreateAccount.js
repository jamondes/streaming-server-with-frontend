import React, { useEffect, useState } from 'react';
import { TextField, Button, Typography } from '@mui/material';
import { useAuth } from './auth';
import { Link, useNavigate } from "react-router-dom";

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

const CreateAccount = () => {
  const navigate = useNavigate();
  let auth = useAuth();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    if (auth.user?.token) {
      return navigate("/");
    }
  }, [auth.user?.token, navigate]);

  const handleSubmit = (e) => {
    setError("");
    e.preventDefault();
    auth.createAccount({ name, email, password }, setError);
  };

  // Prevent rendering anything if we are going to navigate back to Home page
  if (auth.user?.token) {
    return <></>;
  }

  return (
    <div>
      <Typography variant="h4" align="center" gutterBottom>
        Create Account
      </Typography>
      {error && (
        <Typography variant="body1" color="error" align="center" gutterBottom>
          {error}
        </Typography>
      )}
      <form style={styles.form} onSubmit={handleSubmit}>
        <TextField
          label="Name"
          style={styles.inputField}
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
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
          Create Account
        </Button>
        <p>Already have an account? <Link to="/login">Sign in</Link></p>
      </form>
    </div>
  );
};

export default CreateAccount;
