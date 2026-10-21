package com.scamshield_backend;

import jakarta.persistence.*;

@Entity
@Table(name = "link_rules")
public class LinkRule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rule_type")
    private String ruleType;

    @Column(name = "rule_value")
    private String ruleValue;

    @Column(name = "official_domains")
    private String officialDomains;

    @Column(name = "weight")
    private int weight;

    @Column(name = "description_en")
    private String descriptionEn;

    @Column(name = "is_active")
    private boolean active;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getRuleType() { return ruleType; }
    public void setRuleType(String ruleType) { this.ruleType = ruleType; }

    public String getRuleValue() { return ruleValue; }
    public void setRuleValue(String ruleValue) { this.ruleValue = ruleValue; }

    public String getOfficialDomains() { return officialDomains; }
    public void setOfficialDomains(String officialDomains) { this.officialDomains = officialDomains; }

    public int getWeight() { return weight; }
    public void setWeight(int weight) { this.weight = weight; }

    public String getDescriptionEn() { return descriptionEn; }
    public void setDescriptionEn(String descriptionEn) { this.descriptionEn = descriptionEn; }

    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
}