import { AuthProvider } from '@/contexts/AuthContext';
import './globals.css';
export const metadata = {
  title: 'Next.js Auth App',
  description: 'Authentication system with Next.js and MongoDB',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
            {children}
        </AuthProvider>
      </body>
    </html>
  );
}