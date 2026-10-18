package notifications

func securityStateText(value string) ([2]string, bool) {
	switch value {
	case "platform_login_succeeded":
		return [2]string{"Platform session issued", "平台登录会话已签发"}, true
	case "platform_login_new_source":
		return [2]string{"Platform sign-in from a new source", "平台登录来源发生变化"}, true
	case "platform_login_failures":
		return [2]string{"Repeated platform sign-in failures", "平台登录连续失败"}, true
	case "platform_review_pending":
		return [2]string{"Platform sign-in awaiting review", "平台登录等待复核"}, true
	case "platform_review_approved":
		return [2]string{"Platform sign-in approved", "平台登录复核已批准"}, true
	case "platform_review_denied":
		return [2]string{"Platform sign-in denied", "平台登录复核已拒绝"}, true
	case "platform_review_expired":
		return [2]string{"Platform sign-in review expired", "平台登录复核已过期"}, true
	case "platform_review_cancelled":
		return [2]string{"Platform sign-in review cancelled", "平台登录复核已取消"}, true
	case "platform_review_consumed":
		return [2]string{"Platform sign-in permit consumed", "平台登录许可已消费"}, true
	case "platform_review_invalidated":
		return [2]string{"Platform sign-in review invalidated", "平台登录复核已失效"}, true
	case "platform_policy_notified":
		return [2]string{"Platform sign-in policy notification", "平台登录策略通知"}, true
	case "monitoring_firing":
		return [2]string{"Host monitoring alert", "主机监控告警"}, true
	case "monitoring_resolved":
		return [2]string{"Host monitoring recovered", "主机监控已恢复"}, true
	case "pending":
		return [2]string{"Awaiting review", "等待复核"}, true
	case "pending_review":
		return [2]string{"Awaiting command review", "等待命令复核"}, true
	case "running":
		return [2]string{"Running", "运行中"}, true
	case "denied":
		return [2]string{"Denied", "已拒绝"}, true
	case "timed_out":
		return [2]string{"Timed out", "已超时"}, true
	case "amended_approvals_reset":
		return [2]string{"Adjusted; approvals reset", "申请已调整，审批已重置"}, true
	case "asset_review_pending":
		return [2]string{"Asset access review required", "资产访问等待复核"}, true
	case "asset_review_approved":
		return [2]string{"Asset access approved", "资产访问已批准"}, true
	case "asset_review_denied":
		return [2]string{"Asset access denied", "资产访问被拒绝"}, true
	case "asset_review_expired":
		return [2]string{"Asset access request expired", "资产访问请求已过期"}, true
	case "job_review_pending":
		return [2]string{"SSH job review required", "SSH 作业等待复核"}, true
	case "job_review_approved":
		return [2]string{"SSH job approved", "SSH 作业已批准"}, true
	case "job_review_denied":
		return [2]string{"SSH job denied by reviewer", "SSH 作业复核被拒绝"}, true
	case "job_review_expired":
		return [2]string{"SSH job review expired", "SSH 作业复核已过期"}, true
	case "job_command_denied":
		return [2]string{"SSH command blocked by policy", "SSH 命令被策略阻止"}, true
	case "command_review_pending":
		return [2]string{"Interactive command review required", "交互命令等待复核"}, true
	case "command_denied":
		return [2]string{"Interactive command blocked by policy", "交互命令被策略阻止"}, true
	case "command_input_blocked":
		return [2]string{"Unsupported terminal input blocked", "不支持的终端输入被阻止"}, true
	case "command_review_approved":
		return [2]string{"Interactive command approved", "交互命令已批准"}, true
	case "command_review_denied":
		return [2]string{"Interactive command denied by reviewer", "交互命令复核被拒绝"}, true
	case "command_review_expired":
		return [2]string{"Interactive command review expired", "交互命令复核已过期"}, true
	case "command_review_cancelled":
		return [2]string{"Interactive command review cancelled", "交互命令复核已取消"}, true
	case "agent_repair_completed":
		return [2]string{"Host reports Agent repair completed", "主机报告 Agent 修复完成"}, true
	case "agent_repair_failed":
		return [2]string{"Host reports Agent repair failed", "主机报告 Agent 修复失败"}, true
	case "agent_repair_interrupted":
		return [2]string{"Host reports Agent repair interrupted", "主机报告 Agent 修复中断"}, true
	case "agent_history_gap":
		return [2]string{"Host event history gap", "主机事件历史存在缺口"}, true
	case "agent_stream_changed":
		return [2]string{"Host event stream changed", "主机事件流已变更"}, true
	case "agent_log_missing":
		return [2]string{"Host event journal missing", "主机事件日志缺失"}, true
	case "risk_scan_findings":
		return [2]string{"Account scan found risks", "账号扫描发现风险"}, true
	case "risk_scan_clear":
		return [2]string{"Account scan has no open risks", "账号扫描无未处置风险"}, true
	case "risk_scan_failed":
		return [2]string{"Account risk scan failed", "账号风险扫描失败"}, true
	case "risk_scan_cancelled":
		return [2]string{"Account risk scan cancelled", "账号风险扫描已取消"}, true
	case "risk_scan_interrupted":
		return [2]string{"Account risk scan interrupted", "账号风险扫描已中断"}, true
	}
	return [2]string{}, false
}
