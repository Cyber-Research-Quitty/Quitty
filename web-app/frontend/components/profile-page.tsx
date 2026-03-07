'use client';

import { FormEvent, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

import { AppLayout } from './app-layout';
import { AuthResponse, UserProfile } from './types';
import { authApiUrl, authHeaders, clearStoredToken, getStoredToken, persistToken } from '../lib/session';

export function ProfilePage() {
  const router = useRouter();
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [status, setStatus] = useState('Manage your security and personal information with quantum-grade protection.');
  const [name, setName] = useState('');
  const [address, setAddress] = useState('');
  const [phone, setPhone] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  useEffect(() => {
    void loadProfile();
  }, []);

  async function loadProfile() {
    const token = getStoredToken();
    if (!token) {
      router.replace('/');
      return;
    }

    const response = await fetch(`${authApiUrl}/me`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!response.ok) {
      clearStoredToken();
      router.replace('/');
      return;
    }

    const data = (await response.json()) as UserProfile;
    setProfile(data);
    setName(data.name);
    setAddress(data.address);
    setPhone(data.phone);
  }

  async function saveProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const token = getStoredToken();
    const response = await fetch(`${authApiUrl}/me`, {
      method: 'PATCH',
      headers: authHeaders(token),
      body: JSON.stringify({ name, address, phone })
    });

    if (!response.ok) {
      setStatus('Could not update profile.');
      return;
    }

    const data = (await response.json()) as UserProfile;
    setProfile(data);
    setStatus('Profile updated successfully.');
  }

  async function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (newPassword !== confirmPassword) {
      setStatus('New password confirmation does not match.');
      return;
    }
    const token = getStoredToken();
    const response = await fetch(`${authApiUrl}/change-password`, {
      method: 'POST',
      headers: authHeaders(token),
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Password change failed.' }));
      setStatus(error.detail || 'Password change failed.');
      return;
    }

    const data = (await response.json()) as AuthResponse;
    persistToken(data.access_token);
    setCurrentPassword('');
    setNewPassword('');
    setConfirmPassword('');
    setStatus('Password updated successfully.');
  }

  if (!profile) {
    return null;
  }

  return (
    <AppLayout current="profile" profile={profile} status={status}>
      <section className="page-hero compact-hero">
        <h1>Account Profile</h1>
        <p>Manage your security and personal information with quantum-grade protection.</p>
      </section>

      <section className="profile-hero-card">
        <div className="profile-avatar-wrap">
          <div className="profile-avatar">{profile.name.charAt(0).toUpperCase()}</div>
        </div>
        <div className="profile-hero-copy">
          <div className="profile-name-row">
            <strong>{profile.name}</strong>
            <span className="pill accent-pill">Member Since {new Date(profile.created_at).toLocaleDateString()}</span>
          </div>
          <p>{profile.email}</p>
          <p>Role: {profile.role.toUpperCase()}</p>
        </div>
        <div className="security-status">Level 4 Encryption Active</div>
      </section>

      <section className="profile-grid-modern">
        <form className="form-panel" onSubmit={saveProfile}>
          <div className="form-panel-head">Profile Details</div>
          <label>
            <span>Full Name</span>
            <input value={name} onChange={(event) => setName(event.target.value)} required />
          </label>
          <label>
            <span>Shipping Address</span>
            <textarea value={address} onChange={(event) => setAddress(event.target.value)} rows={4} />
          </label>
          <label>
            <span>Phone Number</span>
            <input value={phone} onChange={(event) => setPhone(event.target.value)} required />
          </label>
          <button className="primary-cta" type="submit">Save Profile</button>
        </form>

        <form className="form-panel" onSubmit={changePassword}>
          <div className="form-panel-head">Security Credentials</div>
          <label>
            <span>Current Password</span>
            <input value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} type="password" required />
          </label>
          <label>
            <span>New Password</span>
            <input value={newPassword} onChange={(event) => setNewPassword(event.target.value)} type="password" placeholder="Minimum 12 characters" required />
          </label>
          <label>
            <span>Confirm New Password</span>
            <input value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} type="password" placeholder="Repeat your new password" required />
          </label>
          <div className="security-callout">Use a combination of upper/lower case letters, numbers, and symbols for maximum quantum resilience.</div>
          <button className="primary-cta" type="submit">Update Password</button>
        </form>
      </section>

      <section className="mini-status-grid">
        <article className="mini-status-card">
          <span className="status-icon">✓</span>
          <div>
            <strong>Authenticator</strong>
            <p>2FA status enabled</p>
          </div>
        </article>
        <article className="mini-status-card">
          <span className="status-icon">▣</span>
          <div>
            <strong>Trusted Devices</strong>
            <p>2 active sessions</p>
          </div>
        </article>
        <article className="mini-status-card">
          <span className="status-icon">◔</span>
          <div>
            <strong>Last Login</strong>
            <p>Today via protected session</p>
          </div>
        </article>
      </section>
    </AppLayout>
  );
}
