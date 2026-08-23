package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"easyscan/core"

	"github.com/xuri/excelize/v2"
)

const (
	exportSubdomains = "subdomains"
	exportIPs        = "ips"
	exportPorts      = "ports"
	exportSites      = "sites"
	exportLeaks      = "leaks"
)

var exportAssetOrder = []string{exportSubdomains, exportIPs, exportPorts, exportSites, exportLeaks}

// ExportRequest 定义一次资产导出的格式和范围。AssetTypes 为空表示导出全部资产。
type ExportRequest struct {
	TaskID     string   `json:"task_id"`
	Format     string   `json:"format"`
	AssetTypes []string `json:"asset_types"`
}

type exportData struct {
	Task       core.Task         `json:"task"`
	ExportedAt string            `json:"exported_at"`
	AssetTypes []string          `json:"asset_types"`
	Subdomains *[]core.Subdomain `json:"subdomains,omitempty"`
	IPs        *[]core.IP        `json:"ips,omitempty"`
	Ports      *[]core.Port      `json:"ports,omitempty"`
	Sites      *[]core.Site      `json:"sites,omitempty"`
	Leaks      *[]core.Leak      `json:"leaks,omitempty"`
}

// ExportTask 保留旧版 Wails 接口，默认将全部资产导出为 CSV。
func (a *App) ExportTask(taskID string) (string, error) {
	return a.ExportTaskWithOptions(ExportRequest{TaskID: taskID, Format: "csv"})
}

// ExportTaskWithOptions 将任务资产按指定类型导出为 CSV、JSON 或 XLSX。
func (a *App) ExportTaskWithOptions(req ExportRequest) (string, error) {
	format := strings.ToLower(strings.TrimSpace(req.Format))
	switch format {
	case "csv", "json", "xlsx":
	default:
		return "", fmt.Errorf("不支持的导出格式: %s", req.Format)
	}

	assetTypes, err := normalizeAssetTypes(req.AssetTypes)
	if err != nil {
		return "", err
	}
	data, err := a.loadExportData(req.TaskID, assetTypes)
	if err != nil {
		return "", err
	}

	var content []byte
	switch format {
	case "csv":
		content, err = renderCSV(data)
	case "json":
		content, err = renderJSON(data)
	case "xlsx":
		content, err = renderXLSX(data)
	}
	if err != nil {
		return "", err
	}
	return a.writeExportFile(req.TaskID, format, content)
}

func normalizeAssetTypes(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return append([]string(nil), exportAssetOrder...), nil
	}
	wanted := make(map[string]bool, len(requested))
	for _, item := range requested {
		item = strings.ToLower(strings.TrimSpace(item))
		switch item {
		case exportSubdomains, exportIPs, exportPorts, exportSites, exportLeaks:
			wanted[item] = true
		default:
			return nil, fmt.Errorf("不支持的资产类型: %s", item)
		}
	}
	result := make([]string, 0, len(wanted))
	for _, item := range exportAssetOrder {
		if wanted[item] {
			result = append(result, item)
		}
	}
	return result, nil
}

func (a *App) loadExportData(taskID string, assetTypes []string) (exportData, error) {
	if a.store == nil {
		return exportData{}, fmt.Errorf("存储未初始化")
	}
	if !hexIDRegexp.MatchString(taskID) {
		return exportData{}, fmt.Errorf("非法的任务 ID")
	}
	task, err := a.store.GetTask(taskID)
	if err != nil {
		return exportData{}, fmt.Errorf("任务不存在: %w", err)
	}
	data := exportData{
		Task:       *task,
		ExportedAt: time.Now().Format(time.RFC3339),
		AssetTypes: assetTypes,
	}
	for _, assetType := range assetTypes {
		switch assetType {
		case exportSubdomains:
			items, err := a.store.ListSubdomainsByTask(taskID, -1)
			if err != nil {
				return exportData{}, fmt.Errorf("读取子域名: %w", err)
			}
			data.Subdomains = &items
		case exportIPs:
			items, err := a.store.ListIPsByTask(taskID, -1)
			if err != nil {
				return exportData{}, fmt.Errorf("读取存活 IP: %w", err)
			}
			data.IPs = &items
		case exportPorts:
			items, err := a.store.ListPortsByTask(taskID, -1)
			if err != nil {
				return exportData{}, fmt.Errorf("读取端口: %w", err)
			}
			data.Ports = &items
		case exportSites:
			items, err := a.store.ListSitesByTask(taskID, -1)
			if err != nil {
				return exportData{}, fmt.Errorf("读取站点: %w", err)
			}
			data.Sites = &items
		case exportLeaks:
			items, err := a.store.ListLeaksByTask(taskID, -1)
			if err != nil {
				return exportData{}, fmt.Errorf("读取泄漏结果: %w", err)
			}
			data.Leaks = &items
		}
	}
	return data, nil
}

func renderJSON(data exportData) ([]byte, error) {
	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("生成 JSON: %w", err)
	}
	return append(content, '\n'), nil
}

var csvHeaders = []string{
	"资产类型", "ID", "任务ID", "根域名", "子域名", "IP", "端口", "协议", "服务", "产品",
	"版本", "Banner", "标题", "置信度", "URL", "状态码", "Server", "指纹", "截图路径",
	"泄漏路径", "泄漏类型", "来源", "创建时间",
}

func renderCSV(data exportData) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\uFEFF")
	w := csv.NewWriter(&buf)
	if err := w.Write(csvHeaders); err != nil {
		return nil, fmt.Errorf("生成 CSV: %w", err)
	}
	write := func(row []string) error {
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		return w.Write(row)
	}
	if data.Subdomains != nil {
		for _, item := range *data.Subdomains {
			row := blankCSVRow("子域名", item.ID, item.TaskID, item.CreatedAt)
			row[3], row[4], row[5], row[21] = item.Domain, item.Subdomain, item.IP, item.Source
			if err := write(row); err != nil {
				return nil, fmt.Errorf("生成 CSV: %w", err)
			}
		}
	}
	if data.IPs != nil {
		for _, item := range *data.IPs {
			row := blankCSVRow("存活IP", item.ID, item.TaskID, item.CreatedAt)
			row[3], row[5] = item.Domain, item.IP
			if err := write(row); err != nil {
				return nil, fmt.Errorf("生成 CSV: %w", err)
			}
		}
	}
	if data.Ports != nil {
		for _, item := range *data.Ports {
			row := blankCSVRow("端口", item.ID, item.TaskID, item.CreatedAt)
			row[5], row[6], row[7], row[8] = item.IP, strconv.Itoa(item.Port), item.Protocol, item.Service
			row[9], row[10], row[11], row[12] = item.Product, item.Version, item.Banner, item.Title
			row[13] = strconv.Itoa(item.Confidence)
			if err := write(row); err != nil {
				return nil, fmt.Errorf("生成 CSV: %w", err)
			}
		}
	}
	if data.Sites != nil {
		for _, item := range *data.Sites {
			row := blankCSVRow("站点", item.ID, item.TaskID, item.CreatedAt)
			row[5], row[6], row[12], row[14] = item.IP, strconv.Itoa(item.Port), item.Title, item.URL
			row[15], row[16], row[17], row[18] = strconv.Itoa(item.StatusCode), item.Server, item.Fingerprint, item.Screenshot
			if err := write(row); err != nil {
				return nil, fmt.Errorf("生成 CSV: %w", err)
			}
		}
	}
	if data.Leaks != nil {
		for _, item := range *data.Leaks {
			row := blankCSVRow("泄漏", item.ID, item.TaskID, item.CreatedAt)
			row[14], row[15], row[19], row[20] = item.URL, strconv.Itoa(item.StatusCode), item.Path, item.Type
			if err := write(row); err != nil {
				return nil, fmt.Errorf("生成 CSV: %w", err)
			}
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("生成 CSV: %w", err)
	}
	return buf.Bytes(), nil
}

func blankCSVRow(assetType, id, taskID string, createdAt int64) []string {
	row := make([]string, len(csvHeaders))
	row[0], row[1], row[2], row[22] = assetType, id, taskID, formatTimestamp(createdAt)
	return row
}

type workbookSheet struct {
	name    string
	headers []string
	rows    [][]interface{}
}

func renderXLSX(data exportData) ([]byte, error) {
	f := excelize.NewFile()
	defer f.Close()
	if err := f.SetSheetName("Sheet1", "任务概览"); err != nil {
		return nil, fmt.Errorf("创建 XLSX 概览: %w", err)
	}

	headerStyle, err := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF", Family: "Arial", Size: 10},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"1E9EB3"}, Pattern: 1},
		Border:    []excelize.Border{{Type: "bottom", Color: "176A78", Style: 1}},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center", WrapText: true},
	})
	if err != nil {
		return nil, fmt.Errorf("创建 XLSX 表头样式: %w", err)
	}
	bodyStyle, err := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Family: "Arial", Size: 10},
		Alignment: &excelize.Alignment{Vertical: "top", WrapText: true},
	})
	if err != nil {
		return nil, fmt.Errorf("创建 XLSX 正文样式: %w", err)
	}

	summary := workbookSheet{
		name: "任务概览", headers: []string{"字段", "内容"},
		rows: [][]interface{}{
			{"任务ID", data.Task.ID}, {"目标", data.Task.Target}, {"任务类型", string(data.Task.Type)},
			{"状态", string(data.Task.Status)}, {"进度", data.Task.Progress}, {"阶段", data.Task.Stage},
			{"创建时间", formatTimestamp(data.Task.CreatedAt)}, {"完成时间", formatTimestamp(data.Task.FinishedAt)},
			{"导出时间", data.ExportedAt}, {"资产类型", strings.Join(data.AssetTypes, ", ")},
		},
	}
	if err := writeWorkbookSheet(f, summary, headerStyle, bodyStyle); err != nil {
		return nil, err
	}
	for _, sheet := range exportSheets(data) {
		if _, err := f.NewSheet(sheet.name); err != nil {
			return nil, fmt.Errorf("创建 XLSX 工作表 %s: %w", sheet.name, err)
		}
		if err := writeWorkbookSheet(f, sheet, headerStyle, bodyStyle); err != nil {
			return nil, err
		}
	}
	f.SetActiveSheet(0)
	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, fmt.Errorf("生成 XLSX: %w", err)
	}
	return buf.Bytes(), nil
}

func exportSheets(data exportData) []workbookSheet {
	sheets := make([]workbookSheet, 0, len(data.AssetTypes))
	if data.Subdomains != nil {
		s := workbookSheet{name: "子域名", headers: []string{"ID", "任务ID", "根域名", "子域名", "IP", "来源", "创建时间"}}
		for _, v := range *data.Subdomains {
			s.rows = append(s.rows, []interface{}{v.ID, v.TaskID, v.Domain, v.Subdomain, v.IP, v.Source, formatTimestamp(v.CreatedAt)})
		}
		sheets = append(sheets, s)
	}
	if data.IPs != nil {
		s := workbookSheet{name: "存活IP", headers: []string{"ID", "任务ID", "IP", "关联域名", "创建时间"}}
		for _, v := range *data.IPs {
			s.rows = append(s.rows, []interface{}{v.ID, v.TaskID, v.IP, v.Domain, formatTimestamp(v.CreatedAt)})
		}
		sheets = append(sheets, s)
	}
	if data.Ports != nil {
		s := workbookSheet{name: "端口", headers: []string{"ID", "任务ID", "IP", "端口", "协议", "服务", "产品", "版本", "Banner", "标题", "置信度", "创建时间"}}
		for _, v := range *data.Ports {
			s.rows = append(s.rows, []interface{}{v.ID, v.TaskID, v.IP, v.Port, v.Protocol, v.Service, v.Product, v.Version, v.Banner, v.Title, v.Confidence, formatTimestamp(v.CreatedAt)})
		}
		sheets = append(sheets, s)
	}
	if data.Sites != nil {
		s := workbookSheet{name: "站点", headers: []string{"ID", "任务ID", "IP", "端口", "URL", "标题", "状态码", "Server", "指纹", "截图路径", "创建时间"}}
		for _, v := range *data.Sites {
			s.rows = append(s.rows, []interface{}{v.ID, v.TaskID, v.IP, v.Port, v.URL, v.Title, v.StatusCode, v.Server, v.Fingerprint, v.Screenshot, formatTimestamp(v.CreatedAt)})
		}
		sheets = append(sheets, s)
	}
	if data.Leaks != nil {
		s := workbookSheet{name: "泄漏", headers: []string{"ID", "任务ID", "URL", "泄漏路径", "泄漏类型", "状态码", "创建时间"}}
		for _, v := range *data.Leaks {
			s.rows = append(s.rows, []interface{}{v.ID, v.TaskID, v.URL, v.Path, v.Type, v.StatusCode, formatTimestamp(v.CreatedAt)})
		}
		sheets = append(sheets, s)
	}
	return sheets
}

func writeWorkbookSheet(f *excelize.File, sheet workbookSheet, headerStyle, bodyStyle int) error {
	header := make([]interface{}, len(sheet.headers))
	for i, value := range sheet.headers {
		header[i] = value
	}
	if err := f.SetSheetRow(sheet.name, "A1", &header); err != nil {
		return fmt.Errorf("写入 XLSX 工作表 %s: %w", sheet.name, err)
	}
	for i, row := range sheet.rows {
		cell, _ := excelize.CoordinatesToCellName(1, i+2)
		if err := f.SetSheetRow(sheet.name, cell, &row); err != nil {
			return fmt.Errorf("写入 XLSX 工作表 %s: %w", sheet.name, err)
		}
	}
	lastCol, _ := excelize.ColumnNumberToName(len(sheet.headers))
	lastRow := len(sheet.rows) + 1
	if err := f.SetCellStyle(sheet.name, "A1", lastCol+"1", headerStyle); err != nil {
		return err
	}
	if lastRow > 1 {
		if err := f.SetCellStyle(sheet.name, "A2", fmt.Sprintf("%s%d", lastCol, lastRow), bodyStyle); err != nil {
			return err
		}
	}
	if err := f.SetRowHeight(sheet.name, 1, 24); err != nil {
		return err
	}
	if err := f.SetPanes(sheet.name, &excelize.Panes{Freeze: true, YSplit: 1, TopLeftCell: "A2", ActivePane: "bottomLeft"}); err != nil {
		return err
	}
	if err := f.AutoFilter(sheet.name, fmt.Sprintf("A1:%s%d", lastCol, lastRow), nil); err != nil {
		return err
	}
	for col := range sheet.headers {
		width := utf8.RuneCountInString(sheet.headers[col]) + 4
		for _, row := range sheet.rows {
			if col < len(row) {
				length := utf8.RuneCountInString(fmt.Sprint(row[col])) + 2
				if length > width {
					width = length
				}
			}
		}
		if width < 10 {
			width = 10
		}
		if width > 48 {
			width = 48
		}
		column, _ := excelize.ColumnNumberToName(col + 1)
		if err := f.SetColWidth(sheet.name, column, column, float64(width)); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) writeExportFile(taskID, format string, content []byte) (string, error) {
	dir := filepath.Join(a.configDir, "exports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("创建导出目录: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("设置导出目录权限: %w", err)
	}
	now := time.Now()
	name := fmt.Sprintf("task_%s_%s_%09d.%s", taskID, now.Format("20060102_150405"), now.Nanosecond(), format)
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("创建导出文件: %w", err)
	}
	if _, err = file.Write(content); err != nil {
		file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("写入导出文件: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("关闭导出文件: %w", err)
	}
	return path, nil
}

func formatTimestamp(value int64) string {
	if value <= 0 {
		return ""
	}
	return time.Unix(value, 0).Format(time.RFC3339)
}

// csvSafe 防 CSV 公式注入（CWE-1236）。被扫描站点内容不可信，必须按纯文本写入。
func csvSafe(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}
