import * as React from 'react';
import { Routes, Route } from 'react-router-dom';
import CreateAccount from './CreateAccount';
import Login from './Login';
import VideoStream from './VideoStream';
import { AuthProvider, RequireAuth } from './auth';
import Layout from './Layout';

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/create-account" element={<CreateAccount />} />
          <Route path="/login" element={<Login />} />
          <Route
            path="*"
            element={
              <RequireAuth FallbackComponent={Login}>
                <VideoStream />
              </RequireAuth>
            }
          />
        </Route>
      </Routes>
    </AuthProvider>
  );
}
