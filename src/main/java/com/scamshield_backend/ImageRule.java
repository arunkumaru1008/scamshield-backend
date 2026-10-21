package com.scamshield_backend;

import jakarta.persistence.*;

@Entity
@Table(name = "image_rules")
public class ImageRule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rule_code")
    private String ruleCode;

    @Column(name = "category")
    private String category;

    @Column(name = "detection")
    private String detection;

    @Column(name = "keyword_or_pattern")
    private String keywordOrPattern;

    @Column(name = "match_type")
    private String matchType;

    @Column(name = "weight")
    private int weight;

    @Column(name = "description_en")
    private String descriptionEn;

    @Column(name = "source_url")
    private String sourceUrl;

    @Column(name = "is_active")
    private boolean active;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getRuleCode() { return ruleCode; }
    public void setRuleCode(String ruleCode) { this.ruleCode = ruleCode; }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    public String getDetection() { return detection; }
    public void setDetection(String detection) { this.detection = detection; }

    public String getKeywordOrPattern() { return keywordOrPattern; }
    public void setKeywordOrPattern(String keywordOrPattern) { this.keywordOrPattern = keywordOrPattern; }

    public String getMatchType() { return matchType; }
    public void setMatchType(String matchType) { this.matchType = matchType; }

    public int getWeight() { return weight; }
    public void setWeight(int weight) { this.weight = weight; }

    public String getDescriptionEn() { return descriptionEn; }
    public void setDescriptionEn(String descriptionEn) { this.descriptionEn = descriptionEn; }

    public String getSourceUrl() { return sourceUrl; }
    public void setSourceUrl(String sourceUrl) { this.sourceUrl = sourceUrl; }

    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
}