import { createContext, useContext, useState, useCallback, ReactNode } from 'react';
import { ToastNotification } from '@carbon/react';

// Notification types
export type NotificationType = 'error' | 'success' | 'warning' | 'info';

export interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  subtitle?: string;
  timeout?: number;
}

interface NotificationContextType {
  addNotification: (notification: Omit<Notification, 'id'>) => void;
  removeNotification: (id: string) => void;
  showError: (title: string, subtitle?: string) => void;
  showSuccess: (title: string, subtitle?: string) => void;
  showWarning: (title: string, subtitle?: string) => void;
  showInfo: (title: string, subtitle?: string) => void;
}

const NotificationContext = createContext<NotificationContextType>({
  addNotification: () => {},
  removeNotification: () => {},
  showError: () => {},
  showSuccess: () => {},
  showWarning: () => {},
  showInfo: () => {}
});

export const useNotifications = () => useContext(NotificationContext);

interface NotificationProviderProps {
  children: ReactNode;
}

export function NotificationProvider({ children }: NotificationProviderProps) {
  const [notifications, setNotifications] = useState<Notification[]>([]);

  const addNotification = useCallback((notification: Omit<Notification, 'id'>) => {
    const id = `notification-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const newNotification = { ...notification, id };

    setNotifications(prev => [...prev, newNotification]);

    // Auto-remove after timeout (default 5 seconds)
    const timeout = notification.timeout ?? 5000;
    if (timeout > 0) {
      setTimeout(() => {
        removeNotification(id);
      }, timeout);
    }
  }, []);

  const removeNotification = useCallback((id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  const showError = useCallback((title: string, subtitle?: string) => {
    addNotification({ type: 'error', title, subtitle, timeout: 8000 });
  }, [addNotification]);

  const showSuccess = useCallback((title: string, subtitle?: string) => {
    addNotification({ type: 'success', title, subtitle, timeout: 4000 });
  }, [addNotification]);

  const showWarning = useCallback((title: string, subtitle?: string) => {
    addNotification({ type: 'warning', title, subtitle, timeout: 6000 });
  }, [addNotification]);

  const showInfo = useCallback((title: string, subtitle?: string) => {
    addNotification({ type: 'info', title, subtitle, timeout: 5000 });
  }, [addNotification]);

  return (
    <NotificationContext.Provider
      value={{
        addNotification,
        removeNotification,
        showError,
        showSuccess,
        showWarning,
        showInfo
      }}
    >
      {children}

      {/* Toast notification container */}
      <div
        style={{
          position: 'fixed',
          top: '1rem',
          right: '1rem',
          zIndex: 9999,
          display: 'flex',
          flexDirection: 'column',
          gap: '0.5rem',
          maxWidth: '400px'
        }}
      >
        {notifications.map(notification => (
          <ToastNotification
            key={notification.id}
            kind={notification.type}
            title={notification.title}
            subtitle={notification.subtitle}
            onCloseButtonClick={() => removeNotification(notification.id)}
            style={{
              animation: 'slideIn 0.2s ease-out'
            }}
          />
        ))}
      </div>

      <style>{`
        @keyframes slideIn {
          from {
            transform: translateX(100%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }
      `}</style>
    </NotificationContext.Provider>
  );
}

export default NotificationProvider;
