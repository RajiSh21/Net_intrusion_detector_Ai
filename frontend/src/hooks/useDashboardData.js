import { useState, useEffect } from 'react';

export function useDashboardData() {
  const [stats, setStats] = useState({
    total_packets: 0,
    threat_count: 0,
    distribution: {},
    error: null,
  });
  
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, alertsRes] = await Promise.all([
          fetch('/api/stats'),
          fetch('/api/recent_alerts')
        ]);

        const statsData = await statsRes.json();
        const alertsData = await alertsRes.json();

        if (statsData.error) {
          setStats(prev => ({ ...prev, error: statsData.error }));
        } else {
          setStats({ ...statsData, error: null });
        }

        if (!alertsData.error) {
          setAlerts(alertsData);
        }
      } catch (err) {
        console.error("Error fetching dashboard data:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  return { stats, alerts, loading };
}
