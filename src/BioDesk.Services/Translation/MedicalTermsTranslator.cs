using System.Collections.Generic;

namespace BioDesk.Services.Translation;

/// <summary>
/// Tradutor de termos médicos (Alemão/Inglês → Português Europeu)
/// Baseado em FrequencyList.xls com 1.273 condições de saúde
/// </summary>
public static class MedicalTermsTranslator
{
    // Dicionário principal: Inglês → Português
    private static readonly Dictionary<string, string> _englishToPortuguese = new()
    {
        // A
        { "Vibration-mat 2", "Vibração Terapêutica 2" },
        { "Vibration-mat 3", "Vibração Terapêutica 3" },
        { "Abdominal inflammation", "Inflamação Abdominal" },
        { "Abdominal pain", "Dor Abdominal" },
        { "Abscesses", "Abcessos" },
        { "Abscesses secondary", "Abcessos Secundários" },
        { "Acidosis", "Acidose" },
        { "Acne", "Acne" },
        { "Acne vulgaris", "Acne Vulgar" },
        { "Actinomycosis", "Actinomicose" },
        { "Acute pain", "Dor Aguda" },
        { "Adenoids", "Adenoides" },
        { "Adenoma", "Adenoma" },
        { "Adhesions", "Aderências" },
        { "Adrenal glands", "Glândulas Suprarrenais" },
        { "AIDS", "SIDA" },
        { "Alcoholism", "Alcoolismo" },
        { "Allergies", "Alergias" },
        { "Alopecia", "Alopécia" },
        { "Alzheimer", "Alzheimer" },
        { "Amenorrhea", "Amenorreia" },
        { "Anemia", "Anemia" },
        { "Aneurysm", "Aneurisma" },
        { "Angina", "Angina" },
        { "Anxiety", "Ansiedade" },
        { "Appendicitis", "Apendicite" },
        { "Arrhythmia", "Arritmia" },
        { "Arteriosclerosis", "Arteriosclerose" },
        { "Arthritis", "Artrite" },
        { "Asthma", "Asma" },
        
        // B
        { "Back pain", "Dor nas Costas" },
        { "Bacteria", "Bactérias" },
        { "Bladder", "Bexiga" },
        { "Blood pressure", "Tensão Arterial" },
        { "Bone", "Osso" },
        { "Brain", "Cérebro" },
        { "Bronchitis", "Bronquite" },
        { "Burns", "Queimaduras" },
        
        // C
        { "Cancer", "Cancro" },
        { "Candida", "Candida" },
        { "Cataract", "Catarata" },
        { "Cellulite", "Celulite" },
        { "Chest pain", "Dor no Peito" },
        { "Cholesterol", "Colesterol" },
        { "Chronic fatigue", "Fadiga Crónica" },
        { "Cirrhosis", "Cirrose" },
        { "Cold", "Constipação" },
        { "Colitis", "Colite" },
        { "Colon", "Cólon" },
        { "Constipation", "Obstipação" },
        { "Cough", "Tosse" },
        { "Cramps", "Cãibras" },
        { "Cystitis", "Cistite" },
        
        // D
        { "Dandruff", "Caspa" },
        { "Depression", "Depressão" },
        { "Diabetes", "Diabetes" },
        { "Diarrhea", "Diarreia" },
        { "Digestion", "Digestão" },
        { "Dizziness", "Tonturas" },
        
        // E
        { "Ear", "Ouvido" },
        { "Eczema", "Eczema" },
        { "Edema", "Edema" },
        { "Emphysema", "Enfisema" },
        { "Endometriosis", "Endometriose" },
        { "Epilepsy", "Epilepsia" },
        { "Eye", "Olho" },
        
        // F
        { "Fatigue", "Fadiga" },
        { "Fever", "Febre" },
        { "Fibromyalgia", "Fibromialgia" },
        { "Flu", "Gripe" },
        { "Fungus", "Fungos" },
        
        // G
        { "Gallstones", "Cálculos Biliares" },
        { "Gastritis", "Gastrite" },
        { "Gout", "Gota" },
        { "Gums", "Gengivas" },
        
        // H
        { "Headache", "Dor de Cabeça" },
        { "Heart", "Coração" },
        { "Hemorrhoids", "Hemorroidas" },
        { "Hepatitis", "Hepatite" },
        { "Hernia", "Hérnia" },
        { "Herpes", "Herpes" },
        { "Hypertension", "Hipertensão" },
        { "Hypotension", "Hipotensão" },
        
        // I
        { "Immune system", "Sistema Imunitário" },
        { "Impotence", "Impotência" },
        { "Infection", "Infeção" },
        { "Inflammation", "Inflamação" },
        { "Influenza", "Influenza" },
        { "Insomnia", "Insónia" },
        { "Intestine", "Intestino" },
        
        // J
        { "Joint pain", "Dor Articular" },
        { "Jaundice", "Icterícia" },
        
        // K
        { "Kidney", "Rim" },
        { "Kidney stones", "Cálculos Renais" },
        
        // L
        { "Laryngitis", "Laringite" },
        { "Leukemia", "Leucemia" },
        { "Liver", "Fígado" },
        { "Lung", "Pulmão" },
        { "Lymph", "Linfa" },
        
        // M
        { "Malaria", "Malária" },
        { "Measles", "Sarampo" },
        { "Memory", "Memória" },
        { "Menopause", "Menopausa" },
        { "Migraine", "Enxaqueca" },
        { "Mononucleosis", "Mononucleose" },
        { "Multiple sclerosis", "Esclerose Múltipla" },
        { "Muscle", "Músculo" },
        
        // N
        { "Nausea", "Náusea" },
        { "Nerve", "Nervo" },
        { "Neuralgia", "Neuralgia" },
        { "Neuropathy", "Neuropatia" },
        
        // O
        { "Obesity", "Obesidade" },
        { "Osteoporosis", "Osteoporose" },
        { "Ovary", "Ovário" },
        
        // P
        { "Pain", "Dor" },
        { "Pancreas", "Pâncreas" },
        { "Parkinson", "Parkinson" },
        { "Pneumonia", "Pneumonia" },
        { "Prostate", "Próstata" },
        { "Psoriasis", "Psoríase" },
        
        // R
        { "Rash", "Erupção Cutânea" },
        { "Rheumatism", "Reumatismo" },
        { "Rhinitis", "Rinite" },
        
        // S
        { "Sciatica", "Ciática" },
        { "Sinusitis", "Sinusite" },
        { "Skin", "Pele" },
        { "Spleen", "Baço" },
        { "Stomach", "Estômago" },
        { "Stress", "Stress" },
        { "Stroke", "AVC" },
        
        // T
        { "Tendonitis", "Tendinite" },
        { "Thyroid", "Tiroide" },
        { "Tinnitus", "Acufenos" },
        { "Tonsillitis", "Amigdalite" },
        { "Tooth", "Dente" },
        { "Tuberculosis", "Tuberculose" },
        { "Tumor", "Tumor" },
        
        // U
        { "Ulcer", "Úlcera" },
        { "Urinary tract", "Trato Urinário" },
        { "Uterus", "Útero" },
        
        // V
        { "Varicose veins", "Varizes" },
        { "Vertigo", "Vertigem" },
        { "Virus", "Vírus" },
        
        // W
        { "Warts", "Verrugas" },
        { "Wounds", "Feridas" }
    };

    // Dicionário secundário: Alemão → Português (fallback)
    private static readonly Dictionary<string, string> _germanToPortuguese = new()
    {
        { "Bauchfellentzündung", "Inflamação Abdominal" },
        { "Bauchschmerzen", "Dor Abdominal" },
        { "Abszesse", "Abcessos" },
        { "Vibrationsmatte 2", "Vibração Terapêutica 2" },
        { "Vibrationsmatte 3", "Vibração Terapêutica 3" },
        { "Kopfschmerzen", "Dor de Cabeça" },
        { "Rückenschmerzen", "Dor nas Costas" },
        { "Gelenkschmerzen", "Dor Articular" },
        { "Entzündung", "Inflamação" },
        { "Allergie", "Alergia" },
        { "Asthma", "Asma" },
        { "Diabetes", "Diabetes" },
        { "Grippe", "Gripe" },
        { "Husten", "Tosse" },
        { "Fieber", "Febre" },
        { "Stress", "Stress" },
        { "Depression", "Depressão" },
        { "Angst", "Ansiedade" },
        { "Schlaflosigkeit", "Insónia" },
        { "Müdigkeit", "Fadiga" }
    };

    /// <summary>
    /// Traduz termo médico (Inglês ou Alemão) para Português Europeu
    /// </summary>
    /// <param name="term">Termo em inglês ou alemão</param>
    /// <returns>Tradução em português ou termo original se não encontrar</returns>
    public static string TranslateToPortuguese(string term)
    {
        if (string.IsNullOrWhiteSpace(term))
            return term;

        // Tentar tradução do inglês primeiro
        if (_englishToPortuguese.TryGetValue(term, out var translation))
            return translation;

        // Fallback: tentar alemão
        if (_germanToPortuguese.TryGetValue(term, out translation))
            return translation;

        // Aplicar regras heurísticas para termos não mapeados
        return ApplyHeuristicTranslation(term);
    }

    /// <summary>
    /// Aplica regras heurísticas para traduzir termos não encontrados no dicionário
    /// </summary>
    private static string ApplyHeuristicTranslation(string term)
    {
        // Regra 1: Substituir sufixos comuns
        var translated = term
            .Replace("itis", "ite")       // Sinusitis → Sinusite
            .Replace("osis", "ose")       // Acidosis → Acidose
            .Replace("emia", "emia")      // Anemia → Anemia
            .Replace("algia", "algia");   // Neuralgia → Neuralgia

        // Regra 2: Capitalizar primeira letra (manter restante)
        if (translated.Length > 0)
        {
            translated = char.ToUpper(translated[0]) + translated.Substring(1);
        }

        return translated;
    }

    /// <summary>
    /// Traduz em lote (útil para importação)
    /// </summary>
    public static List<(string Original, string Traducao)> TranslateBatch(IEnumerable<string> terms)
    {
        var results = new List<(string, string)>();
        foreach (var term in terms)
        {
            results.Add((term, TranslateToPortuguese(term)));
        }
        return results;
    }

    /// <summary>
    /// Verifica se tradução está disponível no dicionário
    /// </summary>
    public static bool HasExactTranslation(string term)
    {
        return _englishToPortuguese.ContainsKey(term) || 
               _germanToPortuguese.ContainsKey(term);
    }

    /// <summary>
    /// Adiciona tradução personalizada em runtime (para futuras importações)
    /// </summary>
    public static void AddCustomTranslation(string original, string traducao)
    {
        if (!string.IsNullOrWhiteSpace(original) && !string.IsNullOrWhiteSpace(traducao))
        {
            _englishToPortuguese[original] = traducao;
        }
    }
}
