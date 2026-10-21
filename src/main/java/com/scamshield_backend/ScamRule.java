package com.scamshield_backend;

import jakarta.persistence.*;
import java.time.LocalDate;

@Entity
@Table(name = "scam_rules")
public class ScamRule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rule_code")
    private String ruleCode;

    @Column(name = "category")
    private String category;

    @Column(name = "keyword_or_pattern")
    private String keywordOrPattern;

    @Column(name = "weight")
    private int weight;

    @Column(name = "description_en")
    private String descriptionEn;

    @Column(name = "source_url")
    private String sourceUrl;

    @Column(name = "is_active")
    private boolean active;

    @Column(name = "reviewed_at")
    private LocalDate reviewedAt;

    public Long getId() { return id; }
    public String getRuleCode() { return ruleCode; }
    public String getCategory() { return category; }
    public String getKeywordOrPattern() { return keywordOrPattern; }
    public int getWeight() { return weight; }
    public String getDescriptionEn() { return descriptionEn; }
    public String getSourceUrl() { return sourceUrl; }
    public boolean isActive() { return active; }
    public LocalDate getReviewedAt() { return reviewedAt; }

    public void setId(Long id) { this.id = id; }
    public void setRuleCode(String ruleCode) { this.ruleCode = ruleCode; }
    public void setCategory(String category) { this.category = category; }
    public void setKeywordOrPattern(String keywordOrPattern) { this.keywordOrPattern = keywordOrPattern; }
    public void setWeight(int weight) { this.weight = weight; }
    public void setDescriptionEn(String descriptionEn) { this.descriptionEn = descriptionEn; }
    public void setSourceUrl(String sourceUrl) { this.sourceUrl = sourceUrl; }
    public void setActive(boolean active) { this.active = active; }
    public void setReviewedAt(LocalDate reviewedAt) { this.reviewedAt = reviewedAt; }
}