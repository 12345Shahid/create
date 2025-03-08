-- Supabase SQL setup for Halal AI Chat

-- Create profiles table
CREATE TABLE IF NOT EXISTS profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  first_name TEXT,
  last_name TEXT,
  username TEXT UNIQUE,
  phone_number TEXT,
  birth_date DATE,
  gender TEXT,
  avatar_url TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create RLS policies for profiles table
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view their own profile
CREATE POLICY "Users can view their own profile"
  ON profiles
  FOR SELECT
  USING (auth.uid() = id);

-- Policy: Users can update their own profile
CREATE POLICY "Users can update their own profile"
  ON profiles
  FOR UPDATE
  USING (auth.uid() = id);

-- Policy: Users can insert their own profile
CREATE POLICY "Users can insert their own profile"
  ON profiles
  FOR INSERT
  WITH CHECK (auth.uid() = id);

-- Create user_history table
CREATE TABLE IF NOT EXISTS user_history (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  type TEXT NOT NULL, -- 'research', 'youtube', 'blog', 'developers', 'general'
  input TEXT NOT NULL,
  output TEXT NOT NULL,
  model TEXT DEFAULT 'default',
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index on user_id and timestamp for faster queries
CREATE INDEX IF NOT EXISTS idx_user_history_user_id ON user_history(user_id);
CREATE INDEX IF NOT EXISTS idx_user_history_timestamp ON user_history(timestamp);




-- Create RLS policies for user_history table
ALTER TABLE user_history ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view their own history
CREATE POLICY "Users can view their own history"
  ON user_history
  FOR SELECT
  USING (auth.uid() = user_id);

-- Policy: Users can insert their own history
CREATE POLICY "Users can insert their own history"
  ON user_history
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Create storage bucket for avatars
INSERT INTO storage.buckets (id, name, public) 
VALUES ('avatars', 'avatars', true)
ON CONFLICT (id) DO NOTHING;

-- Set up storage policies for avatars
CREATE POLICY "Avatar images are publicly accessible."
  ON storage.objects FOR SELECT
  USING (bucket_id = 'avatars');

CREATE POLICY "Users can upload their own avatar."
  ON storage.objects FOR INSERT
  WITH CHECK (bucket_id = 'avatars' AND auth.uid() = owner);

CREATE POLICY "Users can update their own avatar."
  ON storage.objects FOR UPDATE
  USING (bucket_id = 'avatars' AND auth.uid() = owner);





















-- Function to handle new user creation
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, created_at, updated_at)
  VALUES (NEW.id, NEW.email, NOW(), NOW());
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to automatically create profile when user signs up
-- Drop the existing trigger if it exists

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

-- Trigger to automatically create profile when user signs up
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ========================================
-- File Management Tables (Folders & Files)
-- ========================================

-- Create folders table
CREATE TABLE IF NOT EXISTS folders (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for faster folder queries
CREATE INDEX IF NOT EXISTS idx_folders_user_id ON folders(user_id);

-- Enable Row-Level Security for folders
ALTER TABLE folders ENABLE ROW LEVEL SECURITY;

-- Folder access policies
CREATE POLICY "Users can view their own folders"
  ON folders FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert their own folders"
  ON folders FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update their own folders"
  ON folders FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users can delete their own folders"
  ON folders FOR DELETE USING (auth.uid() = user_id);

-- Create files table
CREATE TABLE IF NOT EXISTS files (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  folder_id UUID REFERENCES folders(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  content TEXT NOT NULL,
  format TEXT DEFAULT 'text',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for faster file queries
CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);
CREATE INDEX IF NOT EXISTS idx_files_folder_id ON files(folder_id);
CREATE INDEX IF NOT EXISTS idx_files_name ON files(name);

-- Enable Row-Level Security for files
ALTER TABLE files ENABLE ROW LEVEL SECURITY;

-- File access policies
CREATE POLICY "Users can view their own files"
  ON files FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert their own files"
  ON files FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update their own files"
  ON files FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users can delete their own files"
  ON files FOR DELETE USING (auth.uid() = user_id);

-- =====================================
-- Chat Features (Favorites & Shares)
-- =====================================

-- Create chat_favorites table
CREATE TABLE IF NOT EXISTS chat_favorites (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  history_id UUID REFERENCES user_history(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for faster favorite queries
CREATE INDEX IF NOT EXISTS idx_chat_favorites_user_id ON chat_favorites(user_id);
CREATE INDEX IF NOT EXISTS idx_chat_favorites_history_id ON chat_favorites(history_id);

-- Enable Row-Level Security for chat_favorites
ALTER TABLE chat_favorites ENABLE ROW LEVEL SECURITY;

-- Chat favorites policies
CREATE POLICY "Users can view their own favorites"
  ON chat_favorites FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert their own favorites"
  ON chat_favorites FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can delete their own favorites"
  ON chat_favorites FOR DELETE USING (auth.uid() = user_id);

-- Create chat_shares table
CREATE TABLE IF NOT EXISTS chat_shares (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  history_id UUID REFERENCES user_history(id) ON DELETE CASCADE,
  share_token TEXT UNIQUE NOT NULL,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for faster shared chat queries
CREATE INDEX IF NOT EXISTS idx_chat_shares_user_id ON chat_shares(user_id);
CREATE INDEX IF NOT EXISTS idx_chat_shares_history_id ON chat_shares(history_id);
CREATE INDEX IF NOT EXISTS idx_chat_shares_share_token ON chat_shares(share_token);

-- Enable Row-Level Security for chat_shares
ALTER TABLE chat_shares ENABLE ROW LEVEL SECURITY;

-- Chat sharing policies
CREATE POLICY "Users can view their own shared chats"
  ON chat_shares FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Anyone can view shared chats with the token"
  ON chat_shares FOR SELECT USING (is_active = TRUE AND (expires_at IS NULL OR expires_at > NOW()));
CREATE POLICY "Users can insert their own shared chats"
  ON chat_shares FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update their own shared chats"
  ON chat_shares FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users can delete their own shared chats"
  ON chat_shares FOR DELETE USING (auth.uid() = user_id);
















  --SQL scripts for dashboard functionality

-- Add credits column to users table if not exists
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS credits INT DEFAULT 0;

-- Add referral_code column to users table if not exists
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS referral_code TEXT UNIQUE;

-- Add referral_link column to users table if not exists
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS referral_link TEXT;

-- Add referral_credits column to users table if not exists
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS referral_credits INT DEFAULT 0;

-- Add referrer_id column to users table if not exists
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS referrer_id UUID REFERENCES auth.users(id) ON DELETE SET NULL;

-- Create referrals table if not exists
CREATE TABLE IF NOT EXISTS referrals (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  referrer_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  referred_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(referred_id)
);

-- Create function to increment credit
CREATE OR REPLACE FUNCTION public.increment_credit(user_id UUID, amount INT DEFAULT 1)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE auth.users
  SET credits = credits + amount
  WHERE id = user_id;
  
  UPDATE auth.users
  SET referral_credits = referral_credits + amount
  WHERE id = user_id;
END;
$$;

-- Create function to mirror credits to referrer
CREATE OR REPLACE FUNCTION public.mirror_credits()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  referrer_user_id UUID;
BEGIN
  -- Get referrer_id from referrals table
  SELECT referrer_id INTO referrer_user_id
  FROM referrals
  WHERE referred_id = NEW.id;
  
  -- If referrer exists, update their credits
  IF referrer_user_id IS NOT NULL THEN
    UPDATE auth.users
    SET credits = credits + (NEW.credits - OLD.credits),
        referral_credits = referral_credits + (NEW.credits - OLD.credits)
    WHERE id = referrer_user_id AND NEW.credits > OLD.credits;
  END IF;
  
  RETURN NEW;
END;
$$;

-- Create trigger for mirroring credits
DROP TRIGGER IF EXISTS mirror_credits_trigger ON auth.users;

CREATE TRIGGER mirror_credits_trigger
AFTER UPDATE OF credits ON auth.users
FOR EACH ROW
WHEN (NEW.credits > OLD.credits)
EXECUTE FUNCTION public.mirror_credits();

-- Create function to generate referral code on user creation
CREATE OR REPLACE FUNCTION public.generate_referral_code()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  -- Generate unique referral code
  NEW.referral_code = substr(md5(random()::text), 1, 8);
  
  -- Create referral link
  NEW.referral_link = 'https://halal-ai-chat.vercel.app/signup?ref=' || NEW.referral_code;
  
  RETURN NEW;
END;
$$;

-- Create trigger for generating referral code
DROP TRIGGER IF EXISTS generate_referral_code_trigger ON auth.users;

CREATE TRIGGER generate_referral_code_trigger
BEFORE INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION public.generate_referral_code();

-- Create activity table for tracking user actions
CREATE TABLE IF NOT EXISTS activity (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  tool_name TEXT NOT NULL,
  description TEXT NOT NULL,
  credits_used INT DEFAULT 1,
  date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  details JSONB DEFAULT '{}'::jsonb
);

-- Create index on activity table
CREATE INDEX IF NOT EXISTS idx_activity_user_id ON activity(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_date ON activity(date);

-- Enable RLS on activity table
ALTER TABLE activity ENABLE ROW LEVEL SECURITY;

-- Create policies for activity table
CREATE POLICY "Users can view their own activity"
  ON activity FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own activity"
  ON activity FOR INSERT
  WITH CHECK (auth.uid() = user_id);




  



  -- Create halal_compliance_rules table
CREATE TABLE IF NOT EXISTS halal_compliance_rules (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  pattern TEXT NOT NULL,
  replacement TEXT NOT NULL,
  description TEXT,
  category TEXT,
  priority INTEGER DEFAULT 0,
  active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index on priority for faster processing
CREATE INDEX IF NOT EXISTS idx_halal_compliance_rules_priority ON halal_compliance_rules(priority);

-- Insert some default compliance rules
INSERT INTO halal_compliance_rules (pattern, replacement, description, category, priority)
VALUES
  ('\b(alcohol|wine|beer|liquor|whiskey)\b', '[prohibited beverage]', 'Replace alcoholic beverage terms', 'dietary', 10),
  ('\b(pork|bacon|ham|pepperoni)\b', '[non-halal meat]', 'Replace pork-related terms', 'dietary', 10),
  ('\b(gambling|casino|lottery|bet)\b', '[prohibited activity]', 'Replace gambling terms', 'activities', 8),
  ('\b(interest rate|usury|riba)\b', '[non-compliant financial term]', 'Replace interest-related terms', 'financial', 7),
  ('\b(dating|boyfriend|girlfriend)\b', '[relationship]', 'Replace dating terms', 'relationships', 5)
ON CONFLICT (id) DO NOTHING; 



-- Add to supabase_setup.sql

-- Workflows table
CREATE TABLE IF NOT EXISTS workflows (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  steps JSONB NOT NULL DEFAULT '[]',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add index for faster queries
CREATE INDEX IF NOT EXISTS workflows_user_id_idx ON workflows(user_id);

-- Row level security
ALTER TABLE workflows ENABLE ROW LEVEL SECURITY;

-- Policies
CREATE POLICY "Users can view their own workflows" 
  ON workflows FOR SELECT 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own workflows" 
  ON workflows FOR INSERT 
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own workflows" 
  ON workflows FOR UPDATE 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own workflows" 
  ON workflows FOR DELETE 
  USING (auth.uid() = user_id);




CREATE TABLE collaborative_documents (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  title TEXT NOT NULL,
  content TEXT,
  created_by UUID REFERENCES auth.users(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

CREATE TABLE document_collaborators (
  document_id UUID REFERENCES collaborative_documents(id) ON DELETE CASCADE,
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner', 'editor', 'viewer')),
  joined_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()),
  PRIMARY KEY (document_id, user_id)
);

CREATE TABLE document_revisions (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  document_id UUID REFERENCES collaborative_documents(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  created_by UUID REFERENCES auth.users(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);





-- Create collaborative documents table
CREATE TABLE IF NOT EXISTS collaborative_documents (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  title TEXT NOT NULL,
  content TEXT,
  created_by UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- Create document collaborators table
CREATE TABLE IF NOT EXISTS document_collaborators (
  document_id UUID REFERENCES collaborative_documents(id) ON DELETE CASCADE,
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner', 'editor', 'viewer')),
  joined_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()),
  PRIMARY KEY (document_id, user_id)
);

-- Create document revisions table
CREATE TABLE IF NOT EXISTS document_revisions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  document_id UUID REFERENCES collaborative_documents(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  created_by UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- Create RLS policies
ALTER TABLE collaborative_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_collaborators ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_revisions ENABLE ROW LEVEL SECURITY;

-- Document access policy
CREATE POLICY "Users can view documents they collaborate on" ON collaborative_documents
  FOR SELECT USING (
    id IN (
      SELECT document_id FROM document_collaborators WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Document owners can update their documents" ON collaborative_documents
  FOR UPDATE USING (
    created_by = auth.uid() OR 
    EXISTS (
      SELECT 1 FROM document_collaborators 
      WHERE document_id = id AND user_id = auth.uid() AND role = 'editor'
    )
  );

CREATE POLICY "Users can create documents" ON collaborative_documents
  FOR INSERT WITH CHECK (auth.uid() = created_by);

CREATE POLICY "Document owners can delete their documents" ON collaborative_documents
  FOR DELETE USING (created_by = auth.uid());

-- Collaborator policies
CREATE POLICY "Document owners can manage collaborators" ON document_collaborators
  FOR ALL USING (
    document_id IN (
      SELECT id FROM collaborative_documents WHERE created_by = auth.uid()
    )
  );

CREATE POLICY "Users can view collaborators for their documents" ON document_collaborators
  FOR SELECT USING (
    document_id IN (
      SELECT document_id FROM document_collaborators WHERE user_id = auth.uid()
    )
  );

-- Revision policies
CREATE POLICY "Users can view revisions for their documents" ON document_revisions
  FOR SELECT USING (
    document_id IN (
      SELECT document_id FROM document_collaborators WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Users can create revisions for documents they edit" ON document_revisions
  FOR INSERT WITH CHECK (
    document_id IN (
      SELECT document_id FROM document_collaborators 
      WHERE user_id = auth.uid() AND (role = 'owner' OR role = 'editor')
    )
  );





-- Add model column to user_history table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'user_history'
        AND column_name = 'model'
    ) THEN
        ALTER TABLE user_history ADD COLUMN model TEXT DEFAULT 'default';
    END IF;
END $$;





-- Modify user_history table to make user_id nullable for testing
ALTER TABLE user_history DROP CONSTRAINT IF EXISTS user_history_user_id_fkey;
ALTER TABLE user_history ALTER COLUMN user_id DROP NOT NULL;

-- Add a trigger to validate user_id when not in testing mode
CREATE OR REPLACE FUNCTION validate_user_id()
RETURNS TRIGGER AS $$
BEGIN
  -- Skip validation for our test UUID
  IF NEW.user_id = '00000000-0000-4000-a000-000000000000' THEN
    RETURN NEW;
  END IF;
  
  -- Check if user_id exists in auth.users
  IF NEW.user_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM auth.users WHERE id = NEW.user_id
  ) THEN
    RAISE EXCEPTION 'User ID does not exist in auth.users';
  END IF;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger
DROP TRIGGER IF EXISTS user_history_user_id_validation ON user_history;
CREATE TRIGGER user_history_user_id_validation
BEFORE INSERT OR UPDATE ON user_history
FOR EACH ROW
EXECUTE FUNCTION validate_user_id();
