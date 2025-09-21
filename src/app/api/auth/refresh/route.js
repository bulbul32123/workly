// app/api/auth/refresh/route.js
import { NextResponse } from 'next/server';
import connectDB from '@/lib/mongodb';
import RefreshToken from '@/models/RefreshToken';
import User from '@/models/User';
import { signAccessToken } from '@/lib/jwt';
import bcrypt from 'bcryptjs';

const ACCESS_EXPIRE_SECONDS = 15 * 60;
const REFRESH_EXPIRE_SECONDS = 7 * 24 * 60 * 60; 

export async function POST(request) {
  try {
    await connectDB();

    const refreshPlain = request.cookies.get('refreshToken')?.value;
    if (!refreshPlain) {
      return NextResponse.json({ error: 'No refresh token' }, { status: 401 });
    }
    const tokens = await RefreshToken.find({ revoked: false, expiresAt: { $gt: new Date() } });
    let found = null;
    for (const t of tokens) {
      const match = await bcrypt.compare(refreshPlain, t.tokenHash);
      if (match) {
        found = t;
        break;
      }
    }

    if (!found) {
      return NextResponse.json({ error: 'Invalid refresh token' }, { status: 401 });
    }

    const user = await User.findById(found.userId);
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 401 });
    }

    found.revoked = true;
    await found.save();

    const crypto = await import('crypto');
    const newPlain = crypto.randomBytes(64).toString('hex');
    const newHash = await bcrypt.hash(newPlain, 12);
    const newExpiry = new Date(Date.now() + REFRESH_EXPIRE_SECONDS * 1000);
    await RefreshToken.create({ userId: user._id, tokenHash: newHash, expiresAt: newExpiry });

    const newAccess = signAccessToken({ userId: user._id, tokenVersion: user.tokenVersion });

    const res = NextResponse.json({ message: 'Token refreshed', user: { id: user._id, email: user.email, name: user.name }}, { status: 200 });

    const secure = process.env.NODE_ENV === 'production';
    res.cookies.set('accessToken', newAccess, {
      httpOnly: true,
      secure,
      sameSite: 'strict',
      maxAge: ACCESS_EXPIRE_SECONDS,
      path: '/'
    });

    res.cookies.set('refreshToken', newPlain, {
      httpOnly: true,
      secure,
      sameSite: 'strict',
      maxAge: REFRESH_EXPIRE_SECONDS,
      path: '/'
    });

    return res;
  } catch (err) {
    console.error('Refresh error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
