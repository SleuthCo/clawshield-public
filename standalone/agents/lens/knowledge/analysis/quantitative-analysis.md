---
framework: "Quantitative Analysis Methods"
version: "1.0"
domain: "Statistical Analysis"
agent: "coda"
tags: ["statistics", "hypothesis-testing", "regression", "bayesian", "ab-testing", "time-series"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

## Statistical Methods Overview

Quantitative analysis uses mathematical and statistical techniques to describe, infer, and predict patterns in data. The choice of method depends on the research question, data type (continuous, categorical, ordinal), distribution properties, sample size, and study design.

**Descriptive statistics** summarize data: measures of central tendency (mean, median, mode), measures of dispersion (range, variance, standard deviation, interquartile range), measures of shape (skewness, kurtosis), and measures of association (correlation, covariance). Always report descriptive statistics before inferential analyses — they reveal data properties that affect method selection.

**Inferential statistics** draw conclusions about populations from samples. The two major paradigms are frequentist (null hypothesis significance testing and confidence intervals) and Bayesian (posterior probability estimation). Both have legitimate uses; the choice depends on the research question, prior knowledge, and audience conventions.

**Assumptions checking**: Most parametric tests assume: independence of observations, normality of distributions (or residuals), homogeneity of variance, and linearity of relationships. Violations of assumptions can inflate Type I error rates, reduce power, or bias estimates. Check assumptions before selecting and interpreting tests. Normality tests (Shapiro-Wilk, Kolmogorov-Smirnov), variance tests (Levene's, Bartlett's), and residual diagnostics (Q-Q plots, residual plots) are standard checks.

## Hypothesis Testing Framework

Null Hypothesis Significance Testing (NHST) is the dominant inferential framework in many fields, despite significant critiques.

**The logic of NHST**: Assume the null hypothesis (H0: no effect) is true. Calculate the probability of observing data as extreme as or more extreme than the actual data, given H0. This probability is the p-value. If p is less than the pre-specified significance level (alpha, typically 0.05), reject H0 in favor of the alternative hypothesis (H1).

**Common misconceptions**: The p-value is NOT the probability that H0 is true. It is NOT the probability that the result occurred by chance. A non-significant result does NOT prove H0. Statistical significance does NOT imply practical significance. A p-value of 0.04 is NOT meaningfully different from 0.06 — the 0.05 threshold is arbitrary and should not create a dichotomy between "significant" and "non-significant."

**Type I and Type II errors**: Type I error (false positive) — rejecting H0 when it is true. Controlled by alpha (typically 0.05, meaning a 5% false positive rate). Type II error (false negative) — failing to reject H0 when it is false. Controlled by statistical power (1 - beta, typically set at 0.80 or higher). The relationship between these errors is a trade-off: reducing one increases the other, holding sample size constant.

**Multiple comparisons problem**: When conducting multiple statistical tests, the probability of at least one false positive increases rapidly (familywise error rate). For k independent tests at alpha = 0.05, the probability of at least one false positive is 1 - (0.95)^k. Corrections include: Bonferroni (divide alpha by the number of tests — conservative), Holm-Bonferroni (sequential — less conservative), Benjamini-Hochberg (controls false discovery rate rather than familywise error rate — appropriate for exploratory analyses), and Tukey's HSD (for post-hoc pairwise comparisons in ANOVA).

**Power analysis**: Statistical power is the probability of detecting a true effect. Factors affecting power: sample size (more is better), effect size (larger effects are easier to detect), significance level (higher alpha increases power but also increases false positives), and measurement precision (reliable measures increase power). Conduct a priori power analysis before data collection to determine required sample size. Report post-hoc power analysis cautiously — observed power is a direct function of the p-value and adds no new information.

## Regression Analysis

Regression models the relationship between a dependent variable and one or more independent variables (predictors).

**Simple linear regression**: Models the linear relationship between one predictor and one continuous outcome: Y = b0 + b1*X + error. b0 is the intercept (predicted Y when X = 0), b1 is the slope (change in Y per unit change in X). R-squared indicates the proportion of variance in Y explained by X. Check assumptions: linearity (scatterplot), independence (Durbin-Watson), normality of residuals (Q-Q plot), homoscedasticity (residual plot), and absence of influential outliers (Cook's distance).

**Multiple linear regression**: Extends to multiple predictors: Y = b0 + b1*X1 + b2*X2 + ... + error. Each coefficient represents the effect of that predictor holding all others constant (partial regression coefficient). Multicollinearity (high correlation between predictors) inflates standard errors and makes coefficients unstable — check with Variance Inflation Factor (VIF > 10 is problematic, VIF > 5 warrants caution). Model selection approaches: theory-driven (include predictors based on domain knowledge), stepwise (automated, prone to overfitting), and information criteria (AIC, BIC — balance fit and parsimony).

**Logistic regression**: For binary outcomes (yes/no, success/failure). Models the log-odds of the outcome as a linear function of predictors. Coefficients are log-odds ratios; exponentiate to get odds ratios for interpretation. An odds ratio of 2.0 means the odds of the outcome are twice as high for a one-unit increase in the predictor. Model fit: Hosmer-Lemeshow test, Nagelkerke R-squared, classification accuracy, and ROC curve (AUC).

**Generalized linear models (GLMs)**: Extend regression to non-normal outcome distributions. Poisson regression for count data. Negative binomial regression for overdispersed count data. Ordinal logistic regression for ordered categories. Multinomial logistic regression for unordered categories. The link function connects the linear predictor to the expected value of the outcome.

**Regression diagnostics**: Residual analysis (patterns indicate model misspecification). Influential observations (leverage, Cook's distance, DFBETAS). Multicollinearity (VIF, condition indices). Heteroscedasticity (Breusch-Pagan test, White's test — use robust standard errors if detected). Non-linearity (component-plus-residual plots — consider polynomial terms or splines).

## Bayesian Inference

Bayesian inference updates prior beliefs with observed data to produce posterior beliefs, using Bayes' theorem: P(theta|data) proportional to P(data|theta) * P(theta).

**Core concepts**: The prior distribution P(theta) represents beliefs about the parameter before seeing data. The likelihood P(data|theta) represents the probability of the observed data given parameter values. The posterior distribution P(theta|data) combines prior and likelihood — it is the updated belief after seeing data. The posterior is always a compromise between the prior and the data, weighted by their relative precision.

**Choosing priors**: Informative priors incorporate domain knowledge (e.g., from previous studies, expert judgment). Non-informative (vague) priors let the data dominate (e.g., flat prior, Jeffreys prior). Weakly informative priors provide mild regularization without dominating the data (recommended by Gelman et al.). Always conduct sensitivity analysis to assess how prior choice affects conclusions.

**Bayesian advantages**: Direct probability statements about parameters ("There is a 95% probability that the effect is between X and Y" — the credible interval, which is what people often mistakenly think a confidence interval means). Natural incorporation of prior knowledge. No reliance on p-values or arbitrary significance thresholds. Handles small samples more gracefully through regularization from priors. Sequential updating — posteriors can be updated as new data arrive.

**Bayes factors**: The ratio of evidence for one hypothesis over another. BF10 = P(data|H1) / P(data|H0). A Bayes factor of 10 means the data are 10 times more likely under H1 than H0. Jeffreys' scale: 1-3 (anecdotal), 3-10 (moderate), 10-30 (strong), 30-100 (very strong), >100 (extreme). Unlike p-values, Bayes factors can provide evidence FOR the null hypothesis.

**Computational methods**: Markov Chain Monte Carlo (MCMC) algorithms (Gibbs sampler, Metropolis-Hastings, Hamiltonian Monte Carlo) generate samples from the posterior distribution when analytical solutions are intractable. Software: Stan (via RStan or PyStan), JAGS, PyMC, brms (R package using Stan). Convergence diagnostics: trace plots, R-hat (potential scale reduction factor — should be close to 1.0), effective sample size, and divergent transitions.

## A/B Testing

A/B testing (randomized controlled experiments in digital contexts) compares the performance of two or more variants to determine which produces better outcomes.

**Design principles**: Define a single primary metric (conversion rate, revenue per user, engagement time). Calculate required sample size based on minimum detectable effect (MDE), baseline conversion rate, desired power, and significance level. Randomly assign users to control (A) and treatment (B) groups. Run the test long enough to achieve the required sample size and to capture temporal variation (weekly cycles, seasonal effects).

**Common pitfalls**: Peeking (checking results before the planned sample size is reached — inflates false positive rate). Use sequential testing methods (group sequential designs or always-valid confidence intervals) if early stopping is needed. Novelty effects (users react differently to new features initially). Network effects (treatment for one user affects outcomes for connected users — common in social platforms). Sample ratio mismatch (unequal assignment to groups — indicates a bug in randomization).

**Statistical analysis**: For conversion rates (binary outcomes), use a two-proportion z-test or chi-square test. For continuous metrics, use a two-sample t-test or Welch's t-test. For revenue metrics (often highly skewed), consider bootstrap confidence intervals, capped metrics, or quantile analysis. CUPED (Controlled-experiment Using Pre-Experiment Data) reduces variance by adjusting for pre-experiment covariates.

**Bayesian A/B testing**: Estimate the posterior distribution of the difference between variants. Report the probability that B is better than A, the expected lift, and the expected loss from choosing either variant. Bayesian approaches avoid the fixed-sample-size requirement and provide more intuitive probability statements.

## Time Series Analysis

Time series data are observations collected sequentially over time. Analysis exploits temporal structure to describe patterns, test hypotheses, and forecast future values.

**Components of time series**: Trend (long-term direction), seasonality (regular periodic patterns), cyclical patterns (irregular medium-term fluctuations), and irregular/residual (random variation). Decomposition methods separate these components for analysis. Classical decomposition assumes additive (Y = T + S + C + I) or multiplicative (Y = T * S * C * I) relationships.

**Stationarity**: Many time series methods require stationarity — constant mean, constant variance, and autocovariance that depends only on lag, not time. The Augmented Dickey-Fuller (ADF) test and KPSS test assess stationarity. Non-stationary series can often be made stationary through differencing (removing trends) or transformation (logarithm for stabilizing variance).

**ARIMA models**: AutoRegressive Integrated Moving Average models combine three components: AR (current value depends on past values), I (differencing to achieve stationarity), and MA (current value depends on past forecast errors). ARIMA(p,d,q): p = AR order, d = differencing order, q = MA order. Seasonal ARIMA adds seasonal components: SARIMA(p,d,q)(P,D,Q)s. Model selection uses AIC/BIC and diagnostic checking of residuals (should be white noise — no autocorrelation, constant variance, normality).

**Causal inference in time series**: Granger causality tests whether past values of X improve predictions of Y beyond past values of Y alone (a statistical notion of predictive causality, not true causation). Interrupted time series analysis assesses the effect of an intervention by modeling the level and trend before and after the intervention. Difference-in-differences combines time series variation with cross-sectional variation for more robust causal inference.

## Effect Sizes and Confidence Intervals

Effect sizes quantify the magnitude of a result, complementing (or replacing) statistical significance.

**Standardized effect sizes**: Cohen's d (mean difference in standard deviation units; small = 0.2, medium = 0.5, large = 0.8 — but these benchmarks are context-dependent). Hedges' g (bias-corrected d for small samples). Pearson's r (correlation coefficient; small = 0.1, medium = 0.3, large = 0.5). Odds ratio and relative risk for binary outcomes. Eta-squared and partial eta-squared for ANOVA (proportion of variance explained).

**Confidence intervals**: A 95% confidence interval means that if the study were repeated many times, 95% of the computed intervals would contain the true parameter value. A wider interval indicates less precision. Non-overlapping confidence intervals between groups suggest a statistically significant difference, but overlapping intervals do not necessarily mean non-significance (a common misinterpretation). Report confidence intervals for all effect sizes — they convey both the estimate and its precision.

**Practical significance**: A statistically significant result may be too small to be meaningful in practice. Define the minimum clinically important difference (MCID) or minimum practically important effect before data collection. Compare the observed effect size and its confidence interval against this threshold. If the entire confidence interval falls below the threshold, the effect is precisely estimated to be too small to matter.

**Effect size interpretation**: Always interpret effect sizes in context. A "small" effect (d = 0.2) may be practically important if it affects millions of people, is costless to implement, or accumulates over time. A "large" effect (d = 0.8) may be less important if it is expensive to achieve, temporary, or affects few people. Benchmarks are starting points, not substitutes for domain-specific judgment.

## Practical Statistical Decision Guide

Selecting the appropriate statistical test depends on the research question, number and type of variables, and data properties.

**Comparing two groups**: Independent samples — t-test (continuous, normal) or Mann-Whitney U (continuous, non-normal) or chi-square/Fisher's exact (categorical). Paired samples — paired t-test (continuous, normal) or Wilcoxon signed-rank (continuous, non-normal) or McNemar's test (categorical).

**Comparing three or more groups**: One-way ANOVA (continuous outcome, one categorical predictor, normal distribution) or Kruskal-Wallis (non-normal). Two-way ANOVA for factorial designs. Repeated measures ANOVA for within-subjects designs (or Friedman test for non-normal). Post-hoc tests (Tukey, Bonferroni, Games-Howell) for pairwise comparisons after a significant omnibus test.

**Associations**: Two continuous variables — Pearson's r (linear, normal) or Spearman's rho (non-linear or ordinal). Two categorical variables — chi-square test of independence or Fisher's exact test (small expected frequencies). Point-biserial correlation for one continuous and one dichotomous variable.

**Multivariate methods**: Factor analysis (identify latent constructs underlying observed variables). Principal component analysis (data reduction). Cluster analysis (identify natural groupings). Structural equation modeling (test complex causal models with latent variables). Multilevel/hierarchical models (nested data — students within schools, measurements within participants).
