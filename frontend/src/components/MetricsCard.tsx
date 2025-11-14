import React from 'react';
import type { LucideProps } from 'lucide-react';

interface MetricsCardProps {
  title: string;
  value: string | number;
  icon: React.ComponentType<LucideProps>;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  color?: 'primary' | 'success' | 'warning' | 'danger' | 'info';
  subtitle?: string;
  badge?: {
    text: string;
    color: 'red' | 'yellow' | 'green' | 'blue' | 'gray';
  };
  onClick?: () => void;
  clickable?: boolean;
}

const colorClasses = {
  primary: {
    bg: 'bg-primary-500/10',
    icon: 'text-primary-400',
    border: 'border-primary-500/20',
  },
  success: {
    bg: 'bg-green-500/10',
    icon: 'text-green-400',
    border: 'border-green-500/20',
  },
  warning: {
    bg: 'bg-yellow-500/10',
    icon: 'text-yellow-400',
    border: 'border-yellow-500/20',
  },
  danger: {
    bg: 'bg-red-500/10',
    icon: 'text-red-400',
    border: 'border-red-500/20',
  },
  info: {
    bg: 'bg-blue-500/10',
    icon: 'text-blue-400',
    border: 'border-blue-500/20',
  },
};

const badgeColors = {
  red: 'bg-red-500/20 text-red-400 border-red-500/30',
  yellow: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  green: 'bg-green-500/20 text-green-400 border-green-500/30',
  blue: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  gray: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const MetricsCard: React.FC<MetricsCardProps> = ({
  title,
  value,
  icon: Icon,
  trend,
  color = 'primary',
  subtitle,
  badge,
  onClick,
  clickable = false,
}) => {
  const colors = colorClasses[color];

  const cardClasses = `card border ${colors.border} hover:border-${color}-500/40 transition-all duration-200 ${
    clickable ? 'cursor-pointer hover:shadow-lg hover:scale-105' : ''
  }`;

  return (
    <div className={cardClasses} onClick={clickable ? onClick : undefined}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center space-x-2 mb-2">
            <div className={`p-2 rounded-lg ${colors.bg}`}>
              <Icon className={`h-5 w-5 ${colors.icon}`} />
            </div>
            {badge && (
              <span className={`px-2 py-1 rounded-md text-xs font-medium border ${badgeColors[badge.color]}`}>
                {badge.text}
              </span>
            )}
          </div>
          <h3 className="text-sm font-medium text-gray-400 mb-1">{title}</h3>
          <div className="flex items-baseline space-x-2">
            <p className="text-2xl font-bold text-white">{value}</p>
            {trend && (
              <span
                className={`text-sm font-medium ${
                  trend.isPositive ? 'text-green-400' : 'text-red-400'
                }`}
              >
                {trend.isPositive ? '↑' : '↓'} {Math.abs(trend.value)}%
              </span>
            )}
          </div>
          {subtitle && <p className="text-xs text-gray-500 mt-1">{subtitle}</p>}
        </div>
      </div>
    </div>
  );
};

export default MetricsCard;

