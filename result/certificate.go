package result

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
)

type Certificate struct {
	IssuerCaID            int       `json:"issuer_ca_id"`
	IssuerName            string    `json:"issuer_name"`
	CommonName            string    `json:"common_name"`
	NameValue             string    `json:"name_value"`
	ID                    int       `json:"id"`
	EntryTimestamp        time.Time `json:"entry_timestamp"`
	NotBefore             time.Time `json:"not_before"`
	NotAfter              time.Time `json:"not_after"`
	SerialNumber          string    `json:"serial_number"`
	NewlyRegisteredDomain string    `json:"nrd,omitempty"`
}

type Certificates []Certificate

func (r Certificates) Table() []byte {
	res := new(bytes.Buffer)
	table := tablewriter.NewWriter(res)

	// Add NRD indicator to header if this is a newly registered domain
	var info []string
	if len(r) > 0 && len(r) <= 2 {
		// Mark as newly registered domain
		info = []string{"Matching", "Logged At", "Not Before", "Not After", "Issuer", "NRD"}
		// Set the NewlyRegisteredDomain field for the single certificate
		r[0].NewlyRegisteredDomain = "likely"
	} else {
		info = []string{"Matching", "Logged At", "Not Before", "Not After", "Issuer"}
	}

	table.SetHeader(info)
	table.SetFooter(info)

	blue := tablewriter.Color(tablewriter.FgHiBlueColor)
	yellow := tablewriter.Color(tablewriter.FgHiYellowColor)
	white := tablewriter.Color(tablewriter.FgWhiteColor)
	red := tablewriter.Color(tablewriter.FgHiRedColor)

	// Set colors for each column
	if len(r) > 0 && len(r) <= 2 {
		table.SetHeaderColor(blue, blue, blue, blue, blue, blue)
		table.SetFooterColor(blue, blue, blue, blue, blue, blue)
		table.SetColumnColor(yellow, white, white, white, white, red)
	} else {
		table.SetHeaderColor(blue, blue, blue, blue, blue)
		table.SetFooterColor(blue, blue, blue, blue, blue)
		table.SetColumnColor(yellow, white, white, white, white)
	}

	for _, cert := range r {
		// Extract issuer organization more safely
		issuerOrg := "Unknown"
		if strings.Contains(cert.IssuerName, "O=") {
			parts := strings.Split(cert.IssuerName, "O=")
			if len(parts) > 1 {
				// Further split by comma and get the first part
				commaParts := strings.Split(parts[1], ",")
				if len(commaParts) > 0 {
					issuerOrg = strings.Trim(commaParts[0], "\"")
				}
			}
		}

		//row := []string{
		//	cert.NameValue,
		//	cert.EntryTimestamp.String()[0:20],
		//	cert.NotBefore.String()[0:10],
		//	cert.NotAfter.String()[0:10],
		//	issuerOrg,
		//}
		row := []string{
			cert.NameValue,
			cert.EntryTimestamp.Format("2006-01-02 15:04:05"),
			cert.NotBefore.Format("2006-01-02"),
			cert.NotAfter.Format("2006-01-02"),
			issuerOrg,
		}		

		// Add NRD indicator if this is the only result
		if len(r) > 0 && len(r) <= 2 {
			row = append(row, cert.NewlyRegisteredDomain)
		}

		table.Append(row)
	}

	table.SetRowLine(true)
	table.SetRowSeparator("—")
	table.Render()

	return res.Bytes()
}

func (r Certificates) JSON() ([]byte, error) {
	// If there's only one entry, mark it as newly registered domain
	if len(r) > 0 && len(r) <= 2 {
		r[0].NewlyRegisteredDomain = "likely"
	}
	
	res, err := json.MarshalIndent(r, "", "\t")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal results: %s", err)
	}

	return res, nil
}

func (r Certificates) CSV() ([]byte, error) {
	res := new(bytes.Buffer)
	w := csv.NewWriter(res)

	// Add NRD to the header if this is a newly registered domain
	var headers []string
	if len(r) > 0 && len(r) <= 2 {
		r[0].NewlyRegisteredDomain = "likely"
		headers = []string{
			"issuer_ca_id", "issuer_name", "common_name", "name_value", "id",
			"entry_timestamp", "not_before", "not_after", "serial_number", "newly_registered_domain",
		}
	} else {
		headers = []string{
			"issuer_ca_id", "issuer_name", "common_name", "name_value", "id",
			"entry_timestamp", "not_before", "not_after", "serial_number",
		}
	}

	err := w.Write(headers)
	if err != nil {
		return nil, fmt.Errorf("failed to write CSV headers: %s", err)
	}

	for _, v := range r {
		row := []string{
			strconv.Itoa(v.IssuerCaID),
			v.IssuerName,
			v.CommonName,
			v.NameValue,
			strconv.Itoa(v.ID),
			v.EntryTimestamp.String(),
			v.NotBefore.String(),
			v.NotAfter.String(),
			v.SerialNumber,
		}
		
		// Add NRD value if this is the only result
		if len(r) > 0 && len(r) <= 2 {
			row = append(row, v.NewlyRegisteredDomain)
		}
		
		err = w.Write(row)
		if err != nil {
			return nil, fmt.Errorf("failed to write CSV content: %s", err)
		}
	}
	w.Flush()

	return res.Bytes(), nil
}

func (r Certificates) Size() int { return len(r) }