/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

type DataAsset struct {
	Id                     string          `json:"id,omitempty"                       yaml:"id,omitempty"`
	Title                  string          `json:"title,omitempty"                    yaml:"title,omitempty"`
	Description            string          `json:"description,omitempty"              yaml:"description,omitempty"`
	Usage                  Usage           `json:"usage,omitempty"                    yaml:"usage,omitempty"`
	Tags                   []string        `json:"tags,omitempty"                     yaml:"tags,omitempty"`
	Origin                 string          `json:"origin,omitempty"                   yaml:"origin,omitempty"`
	Owner                  string          `json:"owner,omitempty"                    yaml:"owner,omitempty"`
	Quantity               Quantity        `json:"quantity,omitempty"                 yaml:"quantity,omitempty"`
	Confidentiality        Confidentiality `json:"confidentiality,omitempty"          yaml:"confidentiality,omitempty"`
	Integrity              Criticality     `json:"integrity,omitempty"                yaml:"integrity,omitempty"`
	Availability           Criticality     `json:"availability,omitempty"             yaml:"availability,omitempty"`
	JustificationCiaRating string          `json:"justification_cia_rating,omitempty" yaml:"justification_cia_rating,omitempty"`
}

func (what DataAsset) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

type ByDataAssetTitleSort []*DataAsset

func (what ByDataAssetTitleSort) Len() int      { return len(what) }
func (what ByDataAssetTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByDataAssetTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}
