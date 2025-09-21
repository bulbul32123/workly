import { NextResponse } from 'next/server';
import connectDB from '@/lib/mongodb';
import RefreshToken from '@/models/RefreshToken';

export async function POST(request) {
  try {
    await connectDB();

    const refreshPlain = request.cookies.get('refreshToken')?.value;
    if (refreshPlain) {
      const tokens = await RefreshToken.find({ revoked: false, expiresAt: { $gt: new Date() } });
      for (const t of tokens) {
        const bcrypt = await import('bcrypt');
        const match = await bcrypt.compare(refreshPlain, t.tokenHash);
        if (match) {
          t.revoked = true;
          await t.save();
          break;
        }
      }
    }

    const res = NextResponse.json({ message: 'Logged out' }, { status: 200 });
    const secure = process.env.NODE_ENV === 'production';
    res.cookies.set('accessToken', '', { httpOnly: true, secure, sameSite: 'strict', maxAge: 0, path: '/' });
    res.cookies.set('refreshToken', '', { httpOnly: true, secure, sameSite: 'strict', maxAge: 0, path: '/' });

    return res;
  } catch (err) {
    console.error('Logout error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
