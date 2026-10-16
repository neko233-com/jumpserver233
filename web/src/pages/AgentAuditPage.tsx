import AgentEvents from "../components/AgentEvents";
import { useAuth } from "../auth/AuthContext";
export default function AgentAuditPage() {
  const { accessToken } = useAuth();
  return (
    <div className="agent-events-page">
      <AgentEvents accessToken={accessToken} />
    </div>
  );
}
